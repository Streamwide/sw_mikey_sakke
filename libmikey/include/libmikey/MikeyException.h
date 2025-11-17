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

#ifndef MIKEYEXCEPTION_H
#define MIKEYEXCEPTION_H

#include <libmikey/MikeyMessage.h>
#include <libmikey/libmikey_config.h>
#include <libmutil/MemObject.h>

/**
 * Base class for all exceptions that may occur in the MIKEY implementation.
 * @author Erik Eliasson, Johan Bilien
 * @version 0.01
 */

#include <libmutil/Exception.h>

class MikeyMessage;
using libmutil::Exception;

class LIBMIKEY_API MikeyException : public Exception {
  public:
    /**
     * @param All exceptions MUST have a std::string describing the
     * 	exception that is suitable to present to the user.
     */
    explicit MikeyException(const char* message);
    ~MikeyException() noexcept override = default;;
};

class LIBMIKEY_API MikeyExceptionUninitialized : public MikeyException {
  public:
    explicit MikeyExceptionUninitialized(const char* msg);
    ~MikeyExceptionUninitialized() noexcept override;
};

class LIBMIKEY_API MikeyExceptionKeyStoreEmpty : public MikeyException {
  public:
    explicit MikeyExceptionKeyStoreEmpty(const char* msg);
    ~MikeyExceptionKeyStoreEmpty() noexcept override;
};

class LIBMIKEY_API MikeyExceptionMessageContent : public MikeyException {
  public:
    explicit MikeyExceptionMessageContent(const char* msg);
    explicit MikeyExceptionMessageContent(MRef<MikeyMessage*> errMsg, const char* msg = "");
    ~MikeyExceptionMessageContent() noexcept override;

    MRef<MikeyMessage*> errorMessage();

  private:
    MRef<MikeyMessage*> errorMessageValue;
};

class LIBMIKEY_API MikeyExceptionMessageLengthException : public MikeyException {
  public:
    explicit MikeyExceptionMessageLengthException(const char* msg);
    ~MikeyExceptionMessageLengthException() noexcept override;
};

class LIBMIKEY_API MikeyExceptionNullPointerException : public MikeyException {
  public:
    explicit MikeyExceptionNullPointerException(const char* msg);
    ~MikeyExceptionNullPointerException() noexcept override;
};

class LIBMIKEY_API MikeyExceptionAuthentication : public MikeyException {
  public:
    explicit MikeyExceptionAuthentication(const char* msg);
    ~MikeyExceptionAuthentication() noexcept override;
};

class LIBMIKEY_API MikeyExceptionUnacceptable : public MikeyException {
  public:
    explicit MikeyExceptionUnacceptable(const char* msg);
    ~MikeyExceptionUnacceptable() noexcept override;
};

class LIBMIKEY_API MikeyExceptionUnimplemented : public MikeyException {
  public:
    explicit MikeyExceptionUnimplemented(const char* msg);
    ~MikeyExceptionUnimplemented() noexcept override;
};

class LIBMIKEY_API MikeyExceptionNoKey : public MikeyException {
  public:
    explicit MikeyExceptionNoKey(const char* msg);
    ~MikeyExceptionNoKey() noexcept override;
};
#endif
