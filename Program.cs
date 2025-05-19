var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddSignalR(); 
builder.WebHost.UseUrls("http://localhost:5076", "https://localhost:7169");  //добавил явные порты

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection(); закоментил на время

app.UseRouting();

app.MapGet("/", () => "Добро пожаловать на сервер escadre.io!"); //добавил обработчика для корневого маршрута (/)

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

//app.MapGet("/weatherforecast", () =>
//{
//    var forecast =  Enumerable.Range(1, 5).Select(index =>
//        new WeatherForecast
//        (
//            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
//            Random.Shared.Next(-20, 55),
//            summaries[Random.Shared.Next(summaries.Length)]
//        ))
//        .ToArray();
//    return forecast;
//})
.WithName("GetWeatherForecast")
.WithOpenApi();

//app.MapControllers();    закоментил 
//app.MapHub<YourMasterHub>("/masterHub"); 
//app.MapHub<MasterServer.Hubs.MasterHub>("/masterhub");   закоментил

app.Use(async (context, next) => { //
    Console.WriteLine($"Получен запрос: {context.Request.Path}"); //
    await next(); //
    Console.WriteLine($"Отправлен ответ: {context.Response.StatusCode}"); //
}); //

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
