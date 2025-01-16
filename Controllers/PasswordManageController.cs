using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SecureBox.Models;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using SecureBox.Data;
using SecureBox.Helpers;

namespace SecureBox.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PasswordManageController : ControllerBase
    {
        private readonly AppDbContext _context;

        public PasswordManageController(AppDbContext context)
        {
            _context = context;
        }

        // GET: api/PasswordManage/user/{userId}
        [HttpGet("user/{userId}")]
        public ActionResult<IEnumerable<object>> GetPasswordsByUserId(int userId)
        {
            var passwords = _context.PasswordManages.Where(p => p.UserId == userId).ToList();

            // Decrypt passwords before returning them
            foreach (var password in passwords)
            {
                if (!string.IsNullOrEmpty(password.ApplicationPassword))
                {
                    password.ApplicationPassword = EncryptionHelper.Decrypt(password.ApplicationPassword);
                }
            }

            if (passwords == null || !passwords.Any())
            {
                return NotFound("No passwords found for this user.");
            }

            // Return the list of passwords with the necessary details
            var result = passwords.Select(p => new
            {
                p.ApplicationName,
                p.ApplicationUserId,
                p.ApplicationPassword // This is now decrypted
            }).ToList();

            return Ok(result);
        }


        // GET: api/PasswordManage/user/{userId}/applicationUser/{applicationUserId}
        [HttpGet("user/{userId}/applicationUser/{applicationUserId}")]
        public ActionResult<object> GetPasswordByUserIdAndApplicationUserId(int userId, string applicationUserId)
        {
            var password = _context.PasswordManages
                                   .FirstOrDefault(p => p.UserId == userId && p.ApplicationUserId == applicationUserId);

            if (password == null)
            {
                return NotFound("Password not found for the specified user and application user.");
            }

            // Decrypt the password before returning it
            if (!string.IsNullOrEmpty(password.ApplicationPassword))
            {
                password.ApplicationPassword = EncryptionHelper.Decrypt(password.ApplicationPassword);
            }

            // Return the password details
            var result = new
            {
                password.ApplicationName,
                password.ApplicationUserId,
                password.ApplicationPassword // This is now decrypted
            };

            return Ok(result);
        }


        // POST: api/PasswordManage
        [HttpPost]
        public ActionResult<PasswordManage> CreatePassword(PasswordManage passwordManage)
        {
            if (passwordManage == null)
            {
                return BadRequest("Invalid password data.");
            }

            // Encrypt the password before saving it
            if (!string.IsNullOrEmpty(passwordManage.ApplicationPassword))
            {
                passwordManage.ApplicationPassword = EncryptionHelper.Encrypt(passwordManage.ApplicationPassword);
            }

            _context.PasswordManages.Add(passwordManage);
            _context.SaveChanges();

            return CreatedAtAction(nameof(GetPasswordsByUserId), new { userId = passwordManage.UserId }, passwordManage);
        }

        // PUT: api/PasswordManage/user/{userId}/applicationUser/{applicationUserId}/{id}
        [HttpPut("user/{userId}/applicationUser/{applicationUserId}/{id}")]
        public IActionResult UpdatePassword(int userId, string applicationUserId, int id, PasswordManage passwordManage)
        {
            if (id != passwordManage.Sno)
            {
                return BadRequest("Password ID mismatch.");
            }

            // Check if the password entry exists for the given UserId and ApplicationUserId
            var existingPassword = _context.PasswordManages
                                           .FirstOrDefault(p => p.Sno == id && p.UserId == userId && p.ApplicationUserId == applicationUserId);

            if (existingPassword == null)
            {
                return NotFound("Password not found for the specified user and application user.");
            }

            // Encrypt the new password before saving it
            if (!string.IsNullOrEmpty(passwordManage.ApplicationPassword))
            {
                existingPassword.ApplicationPassword = EncryptionHelper.Encrypt(passwordManage.ApplicationPassword);
            }

            existingPassword.ApplicationName = passwordManage.ApplicationName;
            existingPassword.ApplicationUserId = passwordManage.ApplicationUserId;

            _context.Entry(existingPassword).State = EntityState.Modified;
            _context.SaveChanges();

            return NoContent();
        }

        // DELETE: api/PasswordManage/user/{userId}/applicationUser/{applicationUserId}/{id}
        [HttpDelete("user/{userId}/applicationUser/{applicationUserId}/{id}")]
        public IActionResult DeletePassword(int userId, string applicationUserId, int id)
        {
            // Find the password entry with the matching UserId and ApplicationUserId
            var password = _context.PasswordManages
                                   .FirstOrDefault(p => p.Sno == id && p.UserId == userId && p.ApplicationUserId == applicationUserId);

            if (password == null)
            {
                return NotFound("Password not found for the specified user and application user.");
            }

            _context.PasswordManages.Remove(password);
            _context.SaveChanges();

            return NoContent();
        }


    }
}
