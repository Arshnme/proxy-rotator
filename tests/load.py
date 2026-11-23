import asyncio, aiohttp, time, sys, collections, os
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
KILL = len(sys.argv) > 2
URL = "http://127.0.0.1:18787/v1beta/models/gemini-x:generateContent"
async def one(s, i, res):
    t = time.perf_counter()
    try:
        if i % 10 == 0:
            async with s.post("http://127.0.0.1:18787/v1beta/models/gemini-x:streamGenerateContent?alt=sse", headers={"x-goog-api-key": "TESTKEY"}, json={"q": i}) as r:
                b = await r.read(); ok = r.status == 200 and b.count(b"chunk") == 5
                res.append((r.status if ok else 599, (time.perf_counter()-t)*1000, r.headers.get("X-Rotator-Proxy"), int(r.headers.get("X-Rotator-Attempts", 0))))
        else:
            async with s.post(URL, headers={"x-goog-api-key": "TESTKEY"}, json={"q": i}) as r:
                b = await r.read(); ok = r.status == 200 and (b"echo" in b)
                res.append((r.status if ok else 599, (time.perf_counter()-t)*1000, r.headers.get("X-Rotator-Proxy"), int(r.headers.get("X-Rotator-Attempts", 0))))
    except Exception as e:
        res.append((0, (time.perf_counter()-t)*1000, repr(e)[:40], 0))
async def main():
    conn = aiohttp.TCPConnector(limit=0)
    res = []
    async with aiohttp.ClientSession(connector=conn) as s:
        async def killer():
            await asyncio.sleep(0.15); open("/tmp/kill_41001", "w").close()
        t0 = time.perf_counter()
        tasks = [one(s, i, res) for i in range(N)]
        if KILL: tasks.append(killer())
        await asyncio.gather(*tasks)
        dt = time.perf_counter() - t0
    st = collections.Counter(r[0] for r in res)
    lat = sorted(r[1] for r in res)
    print("N=%d  time=%.2fs  rps=%.0f" % (N, dt, N/dt))
    print("status:", dict(st))
    print("latency ms p50=%.0f p95=%.0f max=%.0f" % (lat[len(lat)//2], lat[int(len(lat)*.95)], lat[-1]))
    print("per-proxy:", dict(collections.Counter(r[2] for r in res)))
    print("retried requests:", sum(1 for r in res if r[3] > 1))
asyncio.run(main())
