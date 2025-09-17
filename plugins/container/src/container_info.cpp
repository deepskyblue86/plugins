// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <regex>
#include <utility>
#include <algorithm>
#include "container_info.h"

const container_mount_info *container_info::mount_by_idx(uint32_t idx) const
{
    if(idx >= m_mounts.size())
    {
        return NULL;
    }

    return &(m_mounts[idx]);
}

const container_mount_info *
container_info::mount_by_source(const std::string &source) const
{
    // note: linear search
    try
    {
        std::regex pattern(source, std::regex::multiline);
        for(const auto &mntinfo : m_mounts)
        {
            // checks if the pattern matches any part of the string
            if(std::regex_search(mntinfo.m_source, pattern))
            {
                return &mntinfo;
            }
        }
    }
    catch(const std::regex_error &e)
    {
    }

    return nullptr;
}

const container_mount_info *
container_info::mount_by_dest(const std::string &dest) const
{
    // note: linear search
    try
    {
        std::regex pattern(dest, std::regex::multiline);
        for(const auto &mntinfo : m_mounts)
        {
            // checks if the pattern matches any part of the string
            if(std::regex_search(mntinfo.m_dest, pattern))
            {
                return &mntinfo;
            }
        }
    }
    catch(const std::regex_error &e)
    {
    }

    return nullptr;
}

container_health_probe::probe_type
container_info::match_health_probe(const std::string &exe,
                                   const std::vector<std::string> &args) const
{

    auto pred = [&](const container_health_probe &p)
    { return (p.m_exe == exe && p.m_args == args); };

    auto match =
            std::find_if(m_health_probes.begin(), m_health_probes.end(), pred);

    if(match == m_health_probes.end())
    {
        return container_health_probe::PT_NONE;
    }

    return match->m_type;
}
