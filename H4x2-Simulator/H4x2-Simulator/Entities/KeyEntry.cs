// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//


using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Numerics;
using H4x2_TinySDK.Ed25519;
using Microsoft.EntityFrameworkCore;

namespace H4x2_Simulator.Entities;

public class KeyEntry
{
    [Key]
    public string Id  { get; set; }
    public string Entry_S { get; set;}
    public string Entry_R2 { get; set; }
    public long Timestamp { get; set; }
    public string Public { get; set; }
    public List<Ork> Orks { get; set; }
}