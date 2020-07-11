// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef SCREEN_CONFIGURATION_H
#define SCREEN_CONFIGURATION_H

#define MAX_COLUMNS 5

#include <ncurses.h>
#include <math.h>

/*
* TODO:
* - manage import/export current screen config
* - default color management setup
*/
class ScreenConfiguration
{
    public:
        enum sort {time, pid, process, operation, result, duration};

        ScreenConfiguration()
        { 
            // set default view for UI
            columnSort = ScreenConfiguration::time;
            columnAscending = true;
        }

        void setColumnSort(ScreenConfiguration::sort sort) { columnSort = sort; }
        ScreenConfiguration::sort getColumnSort() { return columnSort; }
        void toggleColumnAscending() { columnAscending = !columnAscending; }
        void setColumnAscending(bool asc) { columnAscending = asc; }
        bool getColumnAscending() { return columnAscending; }

    private:
        // UI Control Variables
        sort columnSort;
        bool columnAscending;
};

#endif
