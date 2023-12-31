/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien,
  Copyright (C) 2005 Mikael Magnusson

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
 *          Mikael Magnusson <mikma@users.sourceforge.net>
 */

#ifndef _MLIBMUTIL_CONFIG_H
#define _MLIBMUTIL_CONFIG_H

#ifdef _MSC_VER
#ifndef LIBMUTIL_EXPORTS
#define LIBMUTIL_IMPORTS
#endif
#endif

#if defined(WIN32) && defined(LIBMUTIL_EXPORTS)
#define LIBMUTIL_API __declspec(dllexport)
#elif defined(WIN32) && defined(LIBMUTIL_IMPORTS)
#define LIBMUTIL_API __declspec(dllimport)
#else
#define LIBMUTIL_API
#endif

#if (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1))
#define LIBMUTIL_DEPRECATED __attribute__((__deprecated__))
#else
#define LIBMUTIL_DEPRECATED
#endif /* __GNUC__ */

#endif // _MLIBMUTIL_CONFIG_H
