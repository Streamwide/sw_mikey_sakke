#ifndef UTIL_TIME_MEASURE_H
#define UTIL_TIME_MEASURE_H

class TimeMeasure
{
public:
   TimeMeasure();
   void reset();
   double getDeltaTime();
   double getCumulativeTime();

private:
   double t{0};
};

#endif//UTIL_TIME_MEASURE_H
