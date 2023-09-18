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

#include <libmutil/MemObject.h>
#include <string>

#include <typeinfo>
using namespace std;

namespace libmutil {

MObject::MObject() {
    refLock = new std::mutex();
}

// The reference count should be zero since
// any references to the argument object
// are not referencing us.
MObject::MObject(const MObject&): refCount(0) {
    refLock = new std::mutex();
}

MObject::~MObject() {
    delete refLock;
}

MObject& MObject::operator=(const MObject&) {
    // we don't copy the mutex handle - whe one we already
    // have protects the reference counter we in this object.
    // We also don't copy the reference counter. The value
    // we already have is the correct number of references.
    //
    // Don't delete this method even if it is empty.
    return *this;
}

int MObject::decRefCount() const {
    int refRet;
    {
        std::lock_guard<std::mutex> lock(*refLock);
        refCount--;
        refRet = refCount;
    }
    return refRet;
}

void MObject::incRefCount() const {
    std::lock_guard<std::mutex> lock(*refLock);
    refCount++;
}

int MObject::getRefCount() const {
    return refCount;
}

string MObject::getMemObjectType() const {
    return "(unknown)";
}

int getMemObjectCount() {
    return -1;
}

bool setDebugOutput([[maybe_unused]] bool on) {
    return false;
}

bool getDebugOutputEnabled() {
    return false;
}
} // namespace libmutil