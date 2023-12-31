/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien
  Copyright (C) 2005  Mikael Magnusson

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

#ifndef _MLIBMIKEY_CONFIG_H
#define _MLIBMIKEY_CONFIG_H

#ifdef _MSC_VER
#ifndef LIBMIKEY_EXPORTS
#define LIBMIKEY_IMPORTS
#endif
#endif

#if defined(WIN32) && defined(LIBMIKEY_EXPORTS)
#define LIBMIKEY_API __declspec(dllexport)
#elif defined(WIN32) && defined(LIBMIKEY_IMPORTS)
#define LIBMIKEY_API __declspec(dllimport)
#else
#define LIBMIKEY_API
#endif

#endif // _MLIBMIKEY_CONFIG_H
