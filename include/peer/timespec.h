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

#ifndef FSNP_TIMESPEC_H
#define FSNP_TIMESPEC_H

#include <time.h>

/*
 * Update 't' to the current time
 */
static inline void update_timespec(struct timespec *t)
{
	clock_gettime(CLOCK_MONOTONIC, t);
}

#define NSEC_TO_SEC(ns) ((double)(ns) / 1000000000.)

/*
 * Calculate the delta of two timespecs (b - a)
 */
static inline double calculate_timespec_delta(const struct timespec *a,
                                              const struct timespec *b)
{
	double aa = 0;
	double bb = 0;

	aa = (double)a->tv_sec + NSEC_TO_SEC(a->tv_nsec);
	bb = (double)b->tv_sec + NSEC_TO_SEC(b->tv_nsec);
	return bb - aa;
}

#endif //FSNP_TIMESPEC_H
