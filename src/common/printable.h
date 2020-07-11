// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <iostream>
#include <string>
#include <typeinfo>

struct IPrintable
{
  public:
    virtual const std::string Print() const
    {
        const IPrintable *p = this;
        return std::string(typeid(p).name());
    };

    friend std::ostream& operator<<(std::ostream& stream, const IPrintable& printable);
};