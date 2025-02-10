using Microsoft.EntityFrameworkCore;
using SecureBox.Data;
using SecureBox.Models;
using System.Linq;
using System.Threading.Tasks;

public class UserService
{
    private readonly AppDbContext _context;

    public UserService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<bool> UserExists(string email)
    {
        return await _context.UserDetails.AnyAsync(u => u.UserMailId == email);
    }

    public async Task<int> GetNextUserId()
    {
        int maxUserId = await _context.UserDetails.MaxAsync(u => (int?)u.UserId ?? 0);
        return maxUserId + 1;
    }

    public async Task<UserDetail> GetUserByEmail(string email)
    {
        return await _context.UserDetails.FirstOrDefaultAsync(u => u.UserMailId == email);
    }

    public async Task AddUser(UserDetail user)
    {
        await _context.UserDetails.AddAsync(user);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateUserStatus(string email, bool status)
    {
        var user = await GetUserByEmail(email);
        if (user != null)
        {
            user.UserStatus = status;
            await _context.SaveChangesAsync();
        }
    }

    public async Task UpdateUser(UserDetail user)
    {
        _context.UserDetails.Update(user);
        await _context.SaveChangesAsync();
    }
}
