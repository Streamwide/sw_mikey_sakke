#include <util/time-measure.h>

#if _WIN32
   #define WIN32_LEAN_AND_MEAN
   #include <windows.h>
   #include <mmsystem.h>

   namespace {

   LARGE_INTEGER freq = {{0, 0}};
   struct frequency
   {
      frequency() { timeBeginPeriod(1); QueryPerformanceFrequency( &freq ); }
      ~frequency() { timeEndPeriod(1); }
   }
   once;

   inline double getTimeNow()
   {
      LARGE_INTEGER currentTime;
      QueryPerformanceCounter( &currentTime );

      return (double)currentTime.QuadPart / (double)freq.QuadPart;
   }

   } // windows

#elif __APPLE__
   // TODO: use mach_absolute_time
   #include <sys/time.h>
   
   namespace {

   inline double getTimeNow()
   {
      timeval tv;
      gettimeofday(&tv, 0);

      return tv.tv_sec + (double)tv.tv_usec / 1000000.;
   }

   }
#else
   #include <ctime>
   #include <sys/types.h>

   namespace { // posix

   inline double getTimeNow()
   {
      timespec currentTime;
      clock_gettime( CLOCK_MONOTONIC, &currentTime );

      return currentTime.tv_sec + (double)currentTime.tv_nsec / 1000000000.;
   }

   } // posix
#endif

TimeMeasure::TimeMeasure()  
= default;

void TimeMeasure::reset()
{
   t = getTimeNow();
}

double TimeMeasure::getCumulativeTime()
{
   double now = getTimeNow();

   if( t == 0 )
   {
      t = now;
      return 0;
   }

   double delta = now - t;

   return delta;
}

double TimeMeasure::getDeltaTime()
{
   double now = getTimeNow();

   if( t == 0 )
   {
      t = now;
      return 0;
   }

   double delta = now - t;

   t = now;

   return delta;
}

