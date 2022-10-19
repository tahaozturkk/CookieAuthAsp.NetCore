using CookieAuthentication.Entities;
using CookieAuthentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NETCore.Encrypt.Extensions;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace CookieAuthentication.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly DatabaseContext _databaseContext;
        private readonly IConfiguration _configuration;
  
        public AccountController(DatabaseContext databaseContext, IConfiguration configuration)
        {
            _databaseContext=databaseContext;
            _configuration=configuration;
        }
        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }
        private string DoMD5HashedString(string s)
        {
            string md5Salt = _configuration.GetValue<string>("AppSetting: MD5Salt");
            string salted = s + md5Salt;
            string hashed = salted.MD5();
            return hashed;
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                string hashedPassword = DoMD5HashedString(model.Password);
                User user = _databaseContext.Users.SingleOrDefault(x => x.Username.ToLower() == model.Username.ToLower()
                && x.Password == hashedPassword);
                if (user != null)
                {
                    if (user.Locked)
                    {
                        ModelState.AddModelError("", "Hesap kitli");
                        return View(model);
                    }

                    List<Claim> claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
                    claims.Add(new Claim(ClaimTypes.Name, user.FullName ?? string.Empty));
                    claims.Add(new Claim(ClaimTypes.Role, user.Role));
                    claims.Add(new Claim("Username", user.Username));
                    ClaimsIdentity identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    ClaimsPrincipal principal = new ClaimsPrincipal(identity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Username veya Password geçersiz.");
                }
            }

            return View(model);
        }

        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (_databaseContext.Users.Any(x => x.Username.ToLower() == model.Username.ToLower()))
                {
                    ModelState.AddModelError(nameof(model.Username), "Kullanıcı mevcut");
                    return View(model);
                }
                string hashedPassword = DoMD5HashedString(model.Password);
                User user = new()
                {
                    Username = model.Username,
                    Password = hashedPassword,
                };
                await _databaseContext.Users.AddAsync(user);
                int affectedRowCount = await _databaseContext.SaveChangesAsync();

                if (affectedRowCount == 0)
                {
                    ModelState.AddModelError("", "Kayıt işlemi başarısız.");
                }
                else
                {
                    return RedirectToAction(nameof(Login));
                }
            }

            return View(model);
        }

        public IActionResult Profile()
        {
            ProfileInfoLoader();
            return View();
        }

        private void ProfileInfoLoader()    
        {
            Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
            User user = _databaseContext.Users.FirstOrDefault(x => x.Id == userid);

            ViewData["FullName"] = user.FullName;
        }

        [HttpPost]
        public IActionResult ProfileChangeFullName([Required(ErrorMessage ="Lütfen değiştirmek isteğiniz İsim,soyisim giriniz.")][StringLength(50, ErrorMessage = "Kullanıcı adı en fazla 50 karakter içerebilir.")] string? fullname)
        {
            if (ModelState.IsValid)
            {
                Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
                User user = _databaseContext.Users.FirstOrDefault(x => x.Id == userid);

                user.FullName = fullname;
                _databaseContext.SaveChanges();
                ViewData["result"] ="FullNameChanged";
                return RedirectToAction(nameof(Profile));
            }
            ProfileInfoLoader();
            return View("Profile");
        }
        [HttpPost]
        public IActionResult ProfileChangePassword([Required][MinLength(6)][MaxLength(16)] string? password)
        {
            if (ModelState.IsValid)
            {
                Guid userid = new Guid(User.FindFirstValue(ClaimTypes.NameIdentifier));
                User user = _databaseContext.Users.FirstOrDefault(x => x.Id == userid);
                string hashedPassword = DoMD5HashedString(password);
                user.Password = hashedPassword;
                _databaseContext.SaveChanges();
                ViewData["result"] = "PasswordChanged";
            }
            ProfileInfoLoader();
            return View("Profile");
        }

        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction(nameof(Login));
        }

    }
}
