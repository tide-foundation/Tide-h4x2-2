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

using System;
using System.Threading.Tasks;
using LazyCache;
using Microsoft.Extensions.Caching.Memory;
namespace H4x2_TinySDK.Tools
{
    public class Caching 
    {
        private readonly IAppCache _cache;

        public Caching()
        {
            _cache = new CachingService();
        }

        public async Task<string> AddOrGetCache(string id, string item)
        {
            var entry = await _cache.GetOrAddAsync<string>(id, () => Task.Run(() => item), BuildPolicy());  
            return entry;         
        }
        
        private MemoryCacheEntryOptions BuildPolicy() => (new MemoryCacheEntryOptions())
            .SetPriority(CacheItemPriority.NeverRemove)
            .SetAbsoluteExpiration(DateTimeOffset.Now.AddSeconds(1000)) //TODO : change later
            .RegisterPostEvictionCallback(PostEvictionCallback);

         public void PostEvictionCallback(object key, object value, EvictionReason reason, object state)
        {
            if (reason == EvictionReason.Capacity)
                Console.WriteLine("Evicted due to {0}", reason); // log for troubleshooting

        }
        public void Remove(string id) => _cache.Remove(id);

    
    }
}