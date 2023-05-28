

using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController: BaseApiController
    {
        private readonly DataContext _context;
        private readonly iTokenService _tokenService;

        public AccountController(DataContext context, iTokenService tokenService){
            _tokenService = tokenService;
             _context = context;
        }

        [HttpPost("register")] // Post: api/account/register

        public async Task<ActionResult<UserDTO>> Register(RegisterDTO registerDTO)
        {
           
           if (await UserExists(registerDTO.Username)) return BadRequest("Username is taken");
           
           using var hmac= new HMACSHA512();  

           var user = new AppUser
           {
              UserName = registerDTO.Username.ToLower(),
              PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
              PasswordSalt = hmac.Key
           };

           _context.Users.Add(user);
           await _context.SaveChangesAsync();

           return new UserDTO{
              Username = user.UserName,
              Token = _tokenService.CreateToken(user)
           };
           
        }

        private async Task<bool> UserExists(string username){

            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        [HttpPost("login")]

        public async Task<ActionResult<UserDTO>> Login(LoginDTO loginDTO){
            
            var user= await _context.Users.SingleOrDefaultAsync( x => x.UserName == loginDTO.Username );

            if(user == null) return Unauthorized("invalid username");

            using var hmac= new HMACSHA512(user.PasswordSalt);  
            var computeHash= hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDTO.Password));

            for(int i=0; i<computeHash.Length;i++){
                if (computeHash[i]!= user.PasswordHash[i]) return Unauthorized("invalid password");
            }

              return new UserDTO{
              Username = user.UserName,
              Token = _tokenService.CreateToken(user)
           };

        }

    }
}