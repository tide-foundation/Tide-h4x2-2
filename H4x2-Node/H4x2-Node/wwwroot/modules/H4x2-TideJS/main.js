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


import { getRandom, test1, test2, test3, test4, test5}from "./test/tests.js";

document.getElementById("Test1").addEventListener("click", test1);
document.getElementById("Test2").addEventListener("click", test2);
document.getElementById("Test3").addEventListener("click", test3);
document.getElementById("Test4").addEventListener("click", test4);
document.getElementById("Test5").addEventListener("click", test5);
document.getElementById("Rand").addEventListener("click", getRandom);