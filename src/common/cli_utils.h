// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <iostream>
#include <string>

namespace CLIUtils
{
    // An immediate exit with no cleanup/wind-down
    void FastExit();

    // Prints usage string to terminal
    void DisplayUsage(bool shouldExit);

    template <typename T>
    void ProtectArgNotNull(T& arg, std::string argName)
    {
        if (arg == NULL)
        {
            // TODO: real error logging 
            std::cerr << "ERROR: The argument '" << argName << "' cannot be null." << std::endl << std::endl;
            DisplayUsage(true);
        }
    };
};