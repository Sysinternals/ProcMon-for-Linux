/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef COLUMN_H
#define COLUMN_H

#include <ncurses.h>
#include <panel.h>
#include <string>
#include <vector>

#include "../logging/easylogging++.h"

#define COLUMN_PADDING          2

class Column {
    public:
        Column(int height, int width, int y, int x, std::string columnName);
        ~Column();

        // column property access functions
        int getX() { return x; }
        int getY() { return y; }
        int getWidth() { return width; }
        int getHeight() { return height; }
        std::string getColumnName() { return columnName; }
        std::vector<std::string> getColumnData() { return columnData; }

        // helper functions
        void addLine(std::string value);
        int resize(int height, int width, int x);
        void setLineColor(int y, int cursesColorPair);
        void toggleHeaderHighlight();
        void moveColumn(int x);

        // screen column functions
        void setBackground(int cursesColor);
        void refreshColumn();
        void resetColumn();
        void clearColumn();
        void redrawColumn();
        void hideColumn();
        void showColumn();

    private:
        int height;
        int width;
        int x;
        int y;
        int currentLine;
        bool highlight;
        WINDOW* win;
        PANEL* panel;

        std::string columnName;
        std::vector<std::string> columnData;

        void columnPrintFill(int colorPair, int x, int y, const char * fmt, ...);
};

#endif // SCREEN_H