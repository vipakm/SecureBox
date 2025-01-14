using System;
using System.Collections.Generic;

namespace SecureBox.Models;

public partial class PasswordManage
{
    public int Sno { get; set; }

    public int? UserId { get; set; }

    public string? ApplicationName { get; set; }

    public string? ApplicationUserId { get; set; }

    public string? ApplicationPassword { get; set; }
}
