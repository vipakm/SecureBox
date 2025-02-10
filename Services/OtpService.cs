using System;
using System.Collections.Generic;

namespace SecureBox.Services
{
    public class OtpService
    {
        private static Dictionary<string, int> _otpStorage = new Dictionary<string, int>();

        public int GenerateOtp(string email)
        {
            Random random = new Random();
            int otp = random.Next(100000, 999999);
            _otpStorage[email] = otp;
            return otp;
        }

        public bool ValidateOtp(string email, int otp)
        {
            if (_otpStorage.ContainsKey(email) && _otpStorage[email] == otp)
            {
                _otpStorage.Remove(email);
                return true;
            }
            return false;
        }
    }

}
