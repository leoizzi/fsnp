/*
 *  This file is part of fsnp.
 *
 *  fsnp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  fsnp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with fsnp. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FSNP_COMPILER_H
#define FSNP_COMPILER_H

#define packed __attribute__((packed))
#define EXPORT __attribute__((visibility("default")))
#define constructor __attribute__((constructor))
#define UNUSED(x) (void)x

#ifdef __cplusplus
#define FSNP_BEGIN_DECL extern "C" {
#define FSNP_END_DECL }
#else // !__cplusplus
#define FSNP_BEGIN_DECL
#define FSNP_END_DECL
#endif // __cplusplus

#endif //FSNP_COMPILER_H
