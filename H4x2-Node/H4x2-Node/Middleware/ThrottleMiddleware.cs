using H4x2_Node.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace H4x2_Node.Middleware;

public class ThrottleMiddleware
{
    private readonly RequestDelegate _next;
    private ThrottlingManager _throttlingManager;

    public ThrottleMiddleware(RequestDelegate next)
    {
        _next = next;
        _throttlingManager = new ThrottlingManager();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Request.Query["uid"])) await _next(context); // user did not query a throttled endpoint

        else
        {
            var barredTime = GetBarredTime(context).Value;
            if (!barredTime.Equals(0)) // if throttled
            {
                context.Response.Headers.Add("Access-Control-Allow-Origin", "*"); // TODO: Find a neater way to add this
                context.Response.StatusCode = 429;
                await context.Response.WriteAsync(barredTime.ToString()); // user got throttled
            }
            else
            {
                await _next(context); // user queired a throttled endpoint, but didn't get throttled
            }
        }
    }
    private ActionResult<int> GetBarredTime(HttpContext context)
    {
        return _throttlingManager.Throttle(context.Request.Query["uid"]).GetAwaiter().GetResult();
    }
}

public static class TideMiddlewareExtensions
{
    public static IApplicationBuilder UseThrottling(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ThrottleMiddleware>();
    }
}