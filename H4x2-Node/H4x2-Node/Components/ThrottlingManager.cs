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


using LazyCache;
using Microsoft.Extensions.Caching.Memory;
namespace H4x2_Node.Controllers
{
    public class ThrottlingManager
    {
        public int Allow { get; set; }
        public int Lapse { get; set; }
        public int MaxPenalty { get; set; }
        public int Repeats { get; set; }
        private readonly IAppCache _cache;


        public ThrottlingManager()
        {
            Allow = 5;
            Repeats = 2;
            Lapse = 60; // 1 Minute unit
            MaxPenalty = 60 * 60; // Max 1 hour throttle
            _cache = new CachingService();

        }

        public async Task<int> Throttle(string id)
        {
            var entry = await _cache.GetOrAddAsync<CacheEntry>(id, () => Task.Run(() => new CacheEntry()), BuildPolicy(TimeSpan.FromSeconds(Lapse)));
            if (entry is not null)
            {
                var currentTime = DateTimeOffset.UtcNow;
                bool isThrottled = (entry.Times >= Allow) && (entry.penaltyExpire > currentTime) && (entry.Reps == 0);
                if (!isThrottled)
                {
                    if (entry.Reps > 0)
                        Interlocked.Decrement(ref entry.Reps);
                    else
                    {
                        entry.Reps = Repeats - 1;
                        Interlocked.Increment(ref entry.Times);
                        int penalty = (int)Math.Min(Math.Pow(2, entry.Times - Allow + 2) * Lapse, MaxPenalty);
                        int monitor = (int)Math.Min(Math.Max(Math.Pow(2, entry.Times - Allow + 3), 2) * Lapse, MaxPenalty * 2);

                        entry.penaltyExpire = currentTime.AddSeconds(penalty);
                        if (monitor < MaxPenalty)
                            _cache.Add(id, entry, BuildPolicy(TimeSpan.FromSeconds(monitor)));   // Call Add() with the generated value you want to update into the cache and it will force the item to be replaced         
                    }
                }
                return isThrottled ? (int)entry.penaltyExpire.Subtract(currentTime).TotalSeconds : 0;
            }
            else
                return MaxPenalty;
        }

        public void Remove(string id) => _cache.Remove(id);	// This is called when password is correct


        private MemoryCacheEntryOptions BuildPolicy(TimeSpan timespam) => (new MemoryCacheEntryOptions())
            .SetPriority(CacheItemPriority.NeverRemove) //When the application server is running short of memory, the .NET Core runtime will initiate the clean-up of In-Memory cache items other than the ones set with NeverRemove priority
            .SetSlidingExpiration(timespam)
            .RegisterPostEvictionCallback(PostEvictionCallback);

        public void PostEvictionCallback(object key, object value, EvictionReason reason, object state)
        {
            if (reason == EvictionReason.Capacity)
                Console.WriteLine("Evicted due to {0}", reason); // change to log for troubleshooting

        }
        private class CacheEntry
        {
            public int Times = 0;
            public int Reps = 0;
            public DateTimeOffset penaltyExpire = DateTimeOffset.UtcNow.AddSeconds(new ThrottlingManager().Lapse);
        }
    }
}