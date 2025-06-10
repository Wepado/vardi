Auth
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <title>Вход / Регистрация</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 40px;
    }
    input, button {
      display: block;
      margin: 10px 0;
      padding: 8px;
      width: 300px;
    }
    h1 {
      margin-top: 40px;
    }
    p {
      color: red;
    }
  </style>
</head>
<body>
  <h1>Регистрация</h1>
  <input type="text" id="regUsername" placeholder="Имя пользователя" />
  <input type="password" id="regPassword" placeholder="Пароль" />
  <button onclick="register()">Зарегистрироваться</button>
  <p id="regMessage"></p>

  <h1>Вход</h1>
  <input type="text" id="loginUsername" placeholder="Имя пользователя" />
  <input type="password" id="loginPassword" placeholder="Пароль" />
  <button onclick="login()">Войти</button>
  <p id="loginMessage"></p>

  <script>
    const apiUrl = 'http://localhost:5156';

    async function register() {
      const username = document.getElementById("regUsername").value;
      const password = document.getElementById("regPassword").value;

      const res = await fetch(`${apiUrl}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const msg = await res.text();
      document.getElementById("regMessage").innerText = msg;

      if (res.ok) {
        await login(username, password); // авто-вход после регистрации
      }
    }

    async function login(usernameArg, passwordArg) {
      const username = usernameArg ?? document.getElementById("loginUsername").value;
      const password = passwordArg ?? document.getElementById("loginPassword").value;

      const res = await fetch(`${apiUrl}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("token", data.token);
        window.location.href = "index.html";
      } else {
        document.getElementById("loginMessage").innerText = "Ошибка авторизации";
      }
    }
  </script>
</body>
</html>





Index.html
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Управление заказами</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 20px;
    }

    section {
      margin-bottom: 40px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }
    th, td {
      border: 1px solid #ccc;
      padding: 8px;
      text-align: left;
    }
    th {
      background-color: #f4f4f4;
    }
    fieldset {
      margin-top: 10px;
      padding: 10px;
    }

    label {
      display: block;
      margin-top: 5px;
    }

    input, select, textarea, button {
      width: 100%;
      padding: 5px;
      margin-top: 5px;
    }

    .stats {
      display: flex;
      gap: 20px;
    }

    .stats > div {
      flex: 1;
      background: #fafafa;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }

    .error {
      color: red;
      margin-top: 10px;
    }

    #logout-btn {
      position: fixed;
      bottom: 10px;
      right: 10px;
      padding: 4px 8px;
      font-size: 11px;
      background-color: #f8f8f8;
      border: 1px solid #bbb;
      border-radius: 4px;
      cursor: pointer;
      opacity: 0.8;
      transition: 0.2s ease;
    }

    #logout-btn:hover {
      opacity: 1;
      background-color: #e6e6e6;
    }
  </style>
</head>
<body>

  <h1>Управление заказами</h1>
  <button id="logout-btn" onclick="logout()">Выйти</button>

  <!-- Список заказов -->
  <section>
    <h2>Список заказов</h2>
    <button onclick="loadOrders()">Обновить список</button>
    <table id="orders-table">
      <thead>
        <tr>
          <th>Id</th>
          <th>Игрушка</th>
          <th>Тип проблемы</th>
          <th>Описание</th>
          <th>Клиент</th>
          <th>Статус</th>
          <th>Исполнитель</th>
          <th>Комментарий</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <div id="orders-error" class="error"></div>
  </section>

  <!-- Создание заказа -->
  <section>
    <h2>Создать заказ</h2>
    <fieldset>
      <label>Игрушка: <input type="text" id="create-device" /></label>
      <label>Тип проблемы: <input type="text" id="create-problemType" /></label>
      <label>Описание: <textarea id="create-description"></textarea></label>
      <label>Клиент: <input type="text" id="create-client" /></label>
      <button onclick="createOrder()">Создать</button>
    </fieldset>
    <div id="create-error" class="error"></div>
  </section>

  <!-- Обновление заказа -->
  <section>
    <h2>Обновить заказ</h2>
    <fieldset>
      <label>Id заказа: <input type="text" id="update-id" /></label>
      <label>Статус:
        <select id="update-status">
          <option value="в ожидании">в ожидании</option>
          <option value="в процессе">в процессе</option>
          <option value="выполнено">выполнено</option>
        </select>
      </label>
      <label>Описание: <textarea id="update-description"></textarea></label>
      <label>Исполнитель: <input type="text" id="update-worker" /></label>
      <label>Комментарий: <textarea id="update-comment"></textarea></label>
      <button onclick="updateOrder()">Обновить</button>
    </fieldset>
    <div id="update-error" class="error"></div>
  </section>

  <!-- Статистика -->
  <section>
    <h2>Статистика</h2>
    <button onclick="loadStatistics()">Обновить статистику</button>
    <div class="stats">
      <div><strong>Завершённых заказов:</strong><p id="stat-completeCount">–</p></div>
      <div><strong>Среднее время (часы):</strong><p id="stat-averageTime">–</p></div>
      <div style="flex:2;">
        <strong>Распределение по типам проблем:</strong>
        <ul id="stat-problemDist"></ul>
      </div>
    </div>
    <div id="stat-error" class="error"></div>
  </section>

  <script>
    const apiBase = 'http://localhost:5156';
    const token = localStorage.getItem("token");

    if (!token) location.href = "auth.html";

    const authorizedFetch = async (url, options = {}) => {
      options.headers = { ...(options.headers || {}), 'Authorization': 'Bearer ' + token };
      const res = await fetch(url, options);
      if (res.status === 401) {
        localStorage.removeItem("token");
        location.href = "auth.html";
      }
      return res;
    };

    const logout = () => {
      localStorage.removeItem("token");
      location.href = "auth.html";
    };

    const clearError = id => document.getElementById(id).textContent = '';
    const showError = (id, msg) => document.getElementById(id).textContent = msg;

    const loadOrders = async () => {
      try {
        const res = await authorizedFetch(`${apiBase}/orders`);
        if (!res.ok) throw new Error('Ошибка загрузки заказов');
        const orders = await res.json();
        const tbody = document.querySelector('#orders-table tbody');
        tbody.innerHTML = orders.map(o => `
          <tr>
            <td>${o.id}</td>
            <td>${o.device}</td>
            <td>${o.problemType}</td>
            <td>${o.description}</td>
            <td>${o.client}</td>
            <td>${o.status}</td>
            <td>${o.worker}</td>
            <td>${o.comment}</td>
          </tr>`).join('');
        clearError('orders-error');
      } catch (err) {
        showError('orders-error', err.message);
      }
    };

    const createOrder = async () => {
      try {
        const dto = {
          device: document.getElementById('create-device').value,
          problemType: document.getElementById('create-problemType').value,
          description: document.getElementById('create-description').value,
          client: document.getElementById('create-client').value
        };
        const res = await authorizedFetch(`${apiBase}/orders`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dto)
        });
        if (!res.ok) throw new Error('Не удалось создать заказ');
        alert('Заказ создан');
        clearError('create-error');
        loadOrders();
      } catch (err) {
        showError('create-error', err.message);
      }
    };

    const updateOrder = async () => {
      try {
        const id = document.getElementById('update-id').value;
        const dto = {
          status: document.getElementById('update-status').value,
          description: document.getElementById('update-description').value,
          worker: document.getElementById('update-worker').value,
          comment: document.getElementById('update-comment').value
        };
        const res = await authorizedFetch(`${apiBase}/orders/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(dto)
        });
        if (!res.ok) throw new Error('Не удалось обновить заказ');
        alert('Заказ обновлён');
        clearError('update-error');
        loadOrders();
      } catch (err) {
        showError('update-error', err.message);
      }
    };

    const loadStatistics = async () => {
      try {
        const res = await authorizedFetch(`${apiBase}/statistics`);
        if (!res.ok) throw new Error('Ошибка загрузки статистики');
        const stat = await res.json();
        document.getElementById('stat-completeCount').textContent = stat.completeCount;
        document.getElementById('stat-averageTime').textContent = stat.averageTime.toFixed(2);

        const ul = document.getElementById('stat-problemDist');
        ul.innerHTML = '';
        Object.entries(stat.stat).forEach(([type, count]) => {
          const li = document.createElement('li');
          li.textContent = `${type}: ${count}`;
          ul.appendChild(li);
        });
        clearError('stat-error');
      } catch (err) {
        showError('stat-error', err.message);
      }
    };

    window.addEventListener('DOMContentLoaded', () => {
      loadOrders();
      loadStatistics();
    });
  </script>

</body>
</html>











program.cs
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
// Конфиг
var builder = WebApplication.CreateBuilder(args);
var jwtKey = "T7hxQw9JgB3ZzSpMnXvKqA2sDjVtZyUc"; // Заменить
var keyBytes = Encoding.ASCII.GetBytes(jwtKey);
// CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});
// JWT Auth
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddDbContext<Repository>();
// Добавляем сервис для JWT
builder.Services.AddScoped<JwtService>();
var app = builder.Build();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
// Регистрация
app.MapPost("/register", async (RegisterDTO dto, Repository repo) =>
{
    if (await repo.Users.AnyAsync(u => u.Username == dto.Username))
        return Results.BadRequest("Пользователь уже существует");
    var user = new User
    {
        Username = dto.Username,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
    };
    await repo.Users.AddAsync(user);
    await repo.SaveChangesAsync();
    return Results.Ok("Пользователь зарегистрирован");
});
// Логин
app.MapPost("/login", async (LoginDTO dto, Repository repo, JwtService jwtService) =>
{
    var user = await repo.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);
    if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
        return Results.Unauthorized();
    var token = jwtService.GenerateToken(user.Username);
    return Results.Ok(new { token });
});
// Заказы — доступ только авторизованным
app.MapGet("/orders", async (Repository repo) =>
{
    var orders = await repo.Orders.ToListAsync();
    return Results.Ok(orders);
}).RequireAuthorization();
app.MapGet("/orders/{id}", async (Guid id, Repository repo) =>
{
    var order = await repo.Orders.FindAsync(id);
    return order != null ? Results.Ok(order) : Results.NotFound();
}).RequireAuthorization();
app.MapPost("/orders", async (CreateOrderDTO dto, Repository repo) =>
{
    var order = new Order(dto.Toy, dto.ProblemType, dto.Description, dto.Client);
    await repo.Orders.AddAsync(order);
    await repo.SaveChangesAsync();
    return Results.Ok(order);
}).RequireAuthorization();
app.MapPut("/orders/{id}", async (UpdateOrderDTO dto, Guid id, Repository repo) =>
{
    var order = await repo.Orders.FindAsync(id);
    if (order == null)
        return Results.NotFound();
    order.Status = dto.Status ?? order.Status;
    order.Description = dto.Description ?? order.Description;
    order.Worker = dto.Worker ?? order.Worker;
    order.Comment = dto.Comment ?? order.Comment;
    await repo.SaveChangesAsync();
    return Results.Ok(order);
}).RequireAuthorization();
app.MapGet("/statistics", async (Repository repo) =>
{
    var orders = await repo.Orders.ToListAsync();
    var completeCount = orders.Count(o => o.Status == "выполнено");
    var averageTime = completeCount == 0 ? 0 :
        orders.Where(o => o.Status == "выполнено" && o.EndDate != null)
              .Average(o => (o.EndDate!.Value - o.StartDate).TotalHours);
    var stat = orders.GroupBy(o => o.ProblemType)
                     .ToDictionary(g => g.Key, g => g.Count());
    return Results.Ok(new StatisticDTO(completeCount, averageTime, stat));
}).RequireAuthorization();
app.Run()
// ======== СЕРВИС ДЛЯ JWT ========
class JwtService
{
    private readonly byte[] key;
    public JwtService(IConfiguration config)
    {
        key = Encoding.ASCII.GetBytes(config["JwtKey"] ?? "T7hxQw9JgB3ZzSpMnXvKqA2sDjVtZyUc");
    }
    public string GenerateToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username) }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
// ======== МОДЕЛИ ========
class Order
{
    public Order(string toy, string problemType, string description, string client)
    {
        Id = Guid.NewGuid();
        StartDate = DateTime.UtcNow;
        EndDate = null;
        Toy = toy;
        ProblemType = problemType;
        Description = description;
        Client = client;
        Status = "в ожидании";
        Worker = "не назначен";
        Comment = "";
    }
    public Guid Id { get; set; }
    public DateTime StartDate { get; set; }
    public DateTime? EndDate { get; set; }
    public string Toy { get; set; }
    public string ProblemType { get; set; }
    public string Description { get; set; }
    public string Client { get; set; }
    private string status = "в ожидании";
    public string Status
    {
        get => status;
        set
        {
            if (value == "выполнено" && EndDate == null)
                EndDate = DateTime.UtcNow;
            status = value;
        }
    }
    public string Worker { get; set; }
    public string Comment { get; set; }
}
class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Username { get; set; }
    public string PasswordHash { get; set; }
}
// ======== DTO ========
record RegisterDTO(string Username, string Password);
record LoginDTO(string Username, string Password);
record CreateOrderDTO(string Toy, string ProblemType, string Description, string Client);
record UpdateOrderDTO(string? Status, string? Description, string? Worker, string? Comment);
record StatisticDTO(int CompleteCount, double AverageTime, Dictionary<string, int> Stat);
// ======== Репозиторий (DbContext) ========
class Repository : DbContext
{
    public Repository(DbContextOptions<Repository> options) : base(options) { }
    public DbSet<Order> Orders { get; set; }
    public DbSet<User> Users { get; set; }
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
            optionsBuilder.UseSqlite("Data Source=orders.db");
    }
}
