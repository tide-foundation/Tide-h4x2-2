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
            .SetAbsoluteExpiration(DateTimeOffset.Now.AddSeconds(1200)) //change later
            .RegisterPostEvictionCallback(PostEvictionCallback);

         public void PostEvictionCallback(object key, object value, EvictionReason reason, object state)
        {
            if (reason == EvictionReason.Capacity)
                Console.WriteLine("Evicted due to {0}", reason); // log for troubleshooting

        }
        public void Remove(string id) => _cache.Remove(id);

    
    }
}