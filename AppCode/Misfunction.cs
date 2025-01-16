using System.Security.Claims;

namespace SecureBox.AppCode
{
    public static class Misfunction
    {
        public static string GetSUserCode(this ClaimsPrincipal user)
        {
            var claim = user?.FindFirst("UserId")?.Value;
            return claim ?? "";
        }
    }
}
