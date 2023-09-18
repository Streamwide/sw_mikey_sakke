/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 */

#include <config.h>

#include <cstring>
#include <libmutil/Timestamp.h>

namespace libmutil {

Timestamp ts;

using namespace std;

#define MAX_TIMESTAMPS 256

/*  Timestamps retrieved are number of seconds since 1970
    However, 3GPP requires timestamps from 1900.
    This value is the number of seconds elapsed between 1900 and 1970
*/
#define NTP_EPOCH_OFFSET 2208988800UL

string id_names[25] = {"invite_start",      "invite_end",         "mikey_start",      "mikey_end",   "ringing",
                       "packet_in",         "packet_out",         "tls_start",        "tls_end",     "dh_precompute_start",
                       "dh_precompute_end", "mikey_create_start", "mikey_create_end", "rand_start",  "rand_end",
                       "sign_start",        "sign_end",           "auth_start",       "auth_end",    "mikey_parse_start",
                       "mikey_parse_end",   "tgk_start",          "tgk_end",          "user_accept", "tmp"};

#ifdef WIN32
Timestamp::Timestamp() {}
Timestamp::Timestamp(const Timestamp&) {}
Timestamp& Timestamp::operator=(const Timestamp& other) {}

#else
Timestamp::Timestamp() {
    tz      = new struct timezone;
    values  = new struct timeval[MAX_TIMESTAMPS];
    strings = new string[MAX_TIMESTAMPS + 1];
    ids     = new int32_t[MAX_TIMESTAMPS];
}

Timestamp::Timestamp(const Timestamp& t)
    : index(t.index), auto_id(t.auto_id), startTime(t.startTime), stopTime(t.stopTime), filename(t.filename) {
    tz = new struct timezone;
    memcpy(tz, t.tz, sizeof(struct timezone));

    values = new struct timeval[MAX_TIMESTAMPS];
    memcpy(values, t.values, MAX_TIMESTAMPS * sizeof(struct timeval));

    strings = new string[MAX_TIMESTAMPS + 1];
    for (int i = 0; i < MAX_TIMESTAMPS; ++i)
        strings[i] = t.strings[i];

    ids = new int32_t[MAX_TIMESTAMPS];
    memcpy(ids, t.ids, MAX_TIMESTAMPS * sizeof(int32_t));
}

Timestamp& Timestamp::operator=(const Timestamp& other) {
    if (this == &other) {
        return *this;
    }
    index     = other.index;
    auto_id   = other.auto_id;
    startTime = other.startTime;
    stopTime  = other.stopTime;
    filename  = other.filename;

    memcpy(tz, other.tz, sizeof(struct timezone));
    memcpy(values, other.values, MAX_TIMESTAMPS * sizeof(struct timeval));
    for (int i = 0; i < MAX_TIMESTAMPS; ++i) {
        strings[i] = other.strings[i];
    }
    memcpy(ids, other.ids, MAX_TIMESTAMPS * sizeof(int32_t));

    return *this;
}

uint64_t Timestamp::Get3GPPSecondsNow64() {
    time_t t;
    time(&t);
    uint64_t ts_sec = t + NTP_EPOCH_OFFSET;
    return ts_sec;
}

#endif

#ifdef WIN32
Timestamp::~Timestamp() {}
#else
Timestamp::~Timestamp() {
    delete tz;
    delete[] values;
    delete[] strings;
    delete[] ids;
}
#endif

#ifdef WIN32
void Timestamp::save(uint32_t id) {}
#else
void Timestamp::save(uint32_t id) {
    ids[index] = id;
    gettimeofday(&values[index], tz);
    index = (index + 1) % MAX_TIMESTAMPS;
    // values[ index++ ] = ((uint64_t)tv->tv_sec << 32) |tv->tv_usec;
}
#endif

#ifdef WIN32
void Timestamp::save(string s) {}
#else
void Timestamp::save(const string& s) {
    ids[index] = auto_id--;
    if (-(auto_id + 1) > MAX_TIMESTAMPS)
        auto_id = -1;
    strings[-(auto_id + 1)] = s;
    gettimeofday(&values[index], tz);
    index = (index + 1) % MAX_TIMESTAMPS;
}
#endif

#ifdef WIN32
void Timestamp::print() {}
#else
void Timestamp::print() {
    print(FILE_NAME);
}
#endif

#ifdef WIN32
void Timestamp::print(const std::string& fileName) {}
#else
void Timestamp::print(const std::string& fileName) {
    uint32_t       i;
    struct timeval temp;
    ofstream       file(fileName.c_str());
    file << "Saved timestamps: " << endl;
    temp = values[0];
    for (i = 0; i < index && i < MAX_TIMESTAMPS; ++i) {
        if (ids[i] < 0) {
            string val = strings[-ids[i]];
            file << "  " << val << ":\t" << values[i].tv_sec << ":\t" << values[i].tv_usec << "\t"
                 << (values[i].tv_sec - temp.tv_sec) * 1000000 + values[i].tv_usec - temp.tv_usec << endl;
        } else
            file << "  " << id_names[ids[i]] << ":\t" << values[i].tv_sec << ":\t" << values[i].tv_usec << "\t"
                 << (values[i].tv_sec - temp.tv_sec) * 1000000 + values[i].tv_usec - temp.tv_usec << endl;
        temp = values[i];
    }
}
#endif

#if 0
#ifdef WIN32
	void Timestamp::init(std::string filename, std::string init_data){}
#else
	void Timestamp::init(std::string filename, std::string init_data){
		this->filename=filename;

		ofstream file (&filename[0]);
		//write init_data in file
		file << init_data << endl;
		file.close();
	}
#endif

#ifdef WIN32
	void Timestamp::start(){}
#else
	void Timestamp::start(){
		timeval tim;
		gettimeofday(&tim, NULL);
		startTime=tim.tv_sec + (tim.tv_usec/1000000.0);
	}

#endif

#ifdef WIN32
	void Timestamp::stop(){}
#else
	void Timestamp::stop(){
	timeval tim;
	gettimeofday(&tim, NULL);
	stopTime=tim.tv_sec + (tim.tv_usec/1000000.0);
}
#endif

#ifdef WIN32
	string Timestamp::writeElapsedTime(std::string descr){ return "1"; }
#else
	string Timestamp::writeElapsedTime(std::string descr){
	double elapsedTime = stopTime-startTime;

	//convert to string
	ostringstream Str;
	Str<<elapsedTime;
	string s_elapsedTime(Str.str());

	//enter value into file
	ofstream file (&this->filename[0], ios::app);
	file << descr << ";" << s_elapsedTime <<endl;
	file.close();

	return s_elapsedTime;
}
#endif

#endif

} // namespace libmutil