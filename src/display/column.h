// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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