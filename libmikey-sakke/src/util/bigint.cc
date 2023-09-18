#if 0
ROOT=$(dirname $0)/../../../
${CROSS_PREFIX}g++ -D TEST_BIGINT $(sh $ROOT/build/test-flags.sh $0) $@
exit $?
#endif

#include <util/bigint.h>
#if !BIGINT_SINGLE_THREAD
#include <pthread.h>
#endif

#if TEST_BIGINT
#include <iostream>
#define TRACE(x) std::cerr << pthread_self() << ": " << x << "\n"
template <typename T> T& TracePtr(T& t) { std::cerr << " => " << &t << "\n"; return t; }
#define TRACERC(x,y) ((std::cerr << pthread_self() << ": " << y), TracePtr(x))
#else
#define TRACE(x)
#define TRACERC(x,y) x
#endif

class bigint_scratch_pool
{
#if TRACE
   bigint_scratch_pool()  { TRACE("bigint_scratch_pool:create("<<this<<")"); }
   ~bigint_scratch_pool() { TRACE("bigint_scratch_pool:destroy("<<this<<")"); }
#endif
   static bigint_scratch_pool& get();
   std::list<bigint> chain;
   std::list<bigint>::iterator avail;
   friend class bigint_scratch;
};

#if !BIGINT_SINGLE_THREAD
struct bigint_scratch_pool_history
{
   bigint_scratch_pool_history()
   {
      pthread_mutex_init(&mtx, nullptr);
   }
   bool add_reclaimable_pool(bigint_scratch_pool* pool)
   {
      bool within_limit = true;
      pthread_mutex_lock(&mtx);
      if (pools.size() < 8)
         pools.push_front(pool);
      else
         within_limit = false;
      pthread_mutex_unlock(&mtx);
      TRACE("add_reclaimable_pool("<<pool<<") => "<<within_limit);
      return within_limit;
   }
   bigint_scratch_pool* reclaim_pool()
   {
      bigint_scratch_pool* rc;
      pthread_mutex_lock(&mtx);
      if (pools.empty())
         rc = nullptr;
      else
      {
         rc = pools.front();
         pools.pop_front();
      }
      pthread_mutex_unlock(&mtx);
      TRACE("reclaim_pool() => "<<rc);
      return rc;
   }
   ~bigint_scratch_pool_history()
   {
      for (auto & pool : pools)
      {
         TRACE("Freeing pool ("<<*it<<")");
         delete pool;
      }
      pthread_mutex_destroy(&mtx);
   }
   std::list<bigint_scratch_pool*> pools;
   pthread_mutex_t mtx; // XXX: ideally want an atomic linked-list for reclaim
}
scratch_reclaim;

static pthread_key_t bigint_scratch_key;
static pthread_once_t bigint_scratch_key_once = PTHREAD_ONCE_INIT;
static void free_thread_specific_scratch(bigint_scratch_pool* scratch)
{
   if (!scratch_reclaim.add_reclaimable_pool(scratch))
      delete scratch;
}
static void bigint_scratch_make_key()
{
   pthread_key_create(&bigint_scratch_key, (void(*)(void*)) free_thread_specific_scratch);
}
#endif

bigint_scratch_pool& bigint_scratch_pool::get()
{
 #if BIGINT_SINGLE_THREAD
   static bigint_scratch_pool s;
   return s;
 #else
   pthread_once(&bigint_scratch_key_once, bigint_scratch_make_key);
   if (void* p = pthread_getspecific(bigint_scratch_key))
      return *reinterpret_cast<bigint_scratch_pool*>(p);

   bigint_scratch_pool* scratch = scratch_reclaim.reclaim_pool();
   if (scratch == nullptr)
      scratch = new bigint_scratch_pool;
   pthread_setspecific(bigint_scratch_key, scratch);
   return *scratch;
 #endif
}


bigint_scratch::bigint_scratch()
   : pool(bigint_scratch_pool::get())
{
   if (pool.chain.empty())
   {
      pool.chain.resize(5);
      pool.avail = pool.chain.begin();
   }
   begin = end = pool.avail;
   TRACE("bigint_scratch: <<StartScratch  ("<<this<<") <"<<&pool<<","<<std::distance(end,pool.chain.begin())<<"/"<<pool.chain.size()<<">");
}
void bigint_scratch::release_all()
{
   if (pool.avail != end)
      return; // cannot throw as called by dtor, but this is exceptional
   pool.avail = end = begin;
   TRACE("bigint_scratch:   EndScratch>>  ("<<this<<") <"<<&pool<<","<<std::distance(end,pool.chain.begin())<<"/"<<pool.chain.size()<<">");
}
bigint& bigint_scratch::get()
{
   if (pool.avail != end)
      throw std::runtime_error("Attempt to get bigint from buried scratch scope.");
   if (pool.avail == pool.chain.end())
   {
      pool.chain.emplace_back(0);
      end = pool.avail = pool.chain.end();
      return TRACERC(pool.chain.back(), "scratch("<<this<<")::get");
   }
   else
   {
      bigint& rc = *pool.avail++;
      end = pool.avail;
      return TRACERC(rc, "scratch("<<this<<")::get");
   }
}



#if TEST_BIGINT
#include <iostream>
void another_fn()
{
   bigint_scratch scratch;
   bigint& a = scratch.get();
   bigint& b = scratch.get();
   bigint& c = scratch.get();
   usleep(100*1000);
}
void* test_thread(void*)
{
   bigint_scratch scratch;
   bigint& x = scratch.get();
   bigint& y = scratch.get();
   {
      bigint_scratch inner;
      bigint& abc = inner.get(); // okay
   }
   try
   {
      bigint_scratch inner;
      bigint& cde = scratch.get(); // bad, but won't throw as there is no conflict yet
      bigint& def = inner.get();   // now there is... bang
   }
   catch (std::exception& e)
   {
      TRACE("1: Caught exception: " << e.what());
   }
   try
   {
      bigint_scratch inner;
      bigint& cde = inner.get();    // bad, but won't throw as there is no conflict yet
      bigint& def = scratch.get();  // now there is... bang
   }
   catch (std::exception& e)
   {
      TRACE("2: Caught exception: " << e.what());
   }
   bigint& z = scratch.get();
   another_fn();
   bigint& w = scratch.get();
   usleep(500*1000);
   return 0;
}
int main()
{
   pthread_t t1; pthread_create(&t1, 0, test_thread, 0);
   pthread_t t2; pthread_create(&t2, 0, test_thread, 0);

   pthread_join(t1, 0);
   pthread_join(t2, 0);

   pthread_create(&t1, 0, test_thread, 0);
   pthread_join(t1, 0);

   pthread_create(&t1, 0, test_thread, 0);
   pthread_create(&t2, 0, test_thread, 0);
   pthread_t t3; pthread_create(&t3, 0, test_thread, 0);
   pthread_join(t1, 0);
   pthread_join(t2, 0);
   pthread_join(t3, 0);
}

#endif // TEST_BIGINT

