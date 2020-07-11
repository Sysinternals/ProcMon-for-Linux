// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "printable.h"

std::ostream& operator<<(std::ostream& stream, const IPrintable& printable)
{
    stream << printable.Print();
    return stream;
};