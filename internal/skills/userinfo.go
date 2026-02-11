package skills

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sentinel-agent/sentinel/internal/types"
)

// UserInfoSkill looks up local user account details including groups, last login,
// and admin status.
type UserInfoSkill struct {
	logger zerolog.Logger
}

// NewUserInfoSkill creates a user info skill.
func NewUserInfoSkill(logger zerolog.Logger) *UserInfoSkill {
	return &UserInfoSkill{
		logger: logger.With().Str("skill", "user_info").Logger(),
	}
}

func (u *UserInfoSkill) Name() string { return "user_info" }
func (u *UserInfoSkill) Description() string {
	return "Look up local user account details including groups, last login, and admin status. Use when investigating compromised accounts or unauthorized access."
}

func (u *UserInfoSkill) ParametersSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"username": map[string]interface{}{
				"type":        "string",
				"description": "The local username to look up",
			},
			"detail_level": map[string]interface{}{
				"type":        "string",
				"description": "Level of detail: basic or full (default: basic)",
				"enum":        []string{"basic", "full"},
			},
		},
		"required": []string{"username"},
	}
}

func (u *UserInfoSkill) Validate(params map[string]interface{}) error {
	username, err := GetStringParam(params, "username")
	if err != nil {
		return err
	}
	if username == "" {
		return fmt.Errorf("username must not be empty")
	}
	if strings.ContainsAny(username, ";|&$`\"'\\") {
		return fmt.Errorf("invalid characters in username: %s", username)
	}

	// Validate detail_level if provided.
	if dl, err := GetStringParam(params, "detail_level"); err == nil && dl != "" {
		dl = strings.ToLower(dl)
		if dl != "basic" && dl != "full" {
			return fmt.Errorf("detail_level must be 'basic' or 'full', got: %s", dl)
		}
	}

	return nil
}

func (u *UserInfoSkill) Execute(ctx context.Context, params map[string]interface{}) (*types.ToolResult, error) {
	username, _ := GetStringParam(params, "username")
	detailLevel := "basic"
	if dl, err := GetStringParam(params, "detail_level"); err == nil && dl != "" {
		detailLevel = strings.ToLower(dl)
	}

	u.logger.Info().Str("username", username).Str("detail_level", detailLevel).Msg("looking up user info")

	var output string
	var err error

	switch runtime.GOOS {
	case "linux":
		output, err = u.executeLinux(ctx, username, detailLevel)
	case "windows":
		output, err = u.executeWindows(ctx, username, detailLevel)
	default:
		return &types.ToolResult{Success: false, Error: fmt.Sprintf("unsupported platform: %s", runtime.GOOS)}, nil
	}

	if err != nil {
		return &types.ToolResult{Success: false, Error: err.Error()}, nil
	}

	return &types.ToolResult{
		Success: true,
		Output:  output,
		Data: map[string]interface{}{
			"username":     username,
			"detail_level": detailLevel,
		},
	}, nil
}

// executeLinux gathers user info from /etc/passwd, /etc/group, and the last command.
func (u *UserInfoSkill) executeLinux(ctx context.Context, username, detailLevel string) (string, error) {
	var result strings.Builder
	result.WriteString(fmt.Sprintf("User Info: %s\n", username))
	result.WriteString(strings.Repeat("=", 50) + "\n")

	// --- Parse /etc/passwd for user entry ---
	uid, gid, home, shell, found, err := u.parsePasswd(username)
	if err != nil {
		return "", fmt.Errorf("failed to read /etc/passwd: %w", err)
	}
	if !found {
		return "", fmt.Errorf("user %q not found in /etc/passwd", username)
	}

	result.WriteString(fmt.Sprintf("%-15s %s\n", "Username:", username))
	result.WriteString(fmt.Sprintf("%-15s %s\n", "UID:", uid))
	result.WriteString(fmt.Sprintf("%-15s %s\n", "GID:", gid))
	result.WriteString(fmt.Sprintf("%-15s %s\n", "Home:", home))
	result.WriteString(fmt.Sprintf("%-15s %s\n", "Shell:", shell))

	// --- Parse /etc/group for group memberships ---
	groups, isAdmin := u.parseGroups(username)
	result.WriteString(fmt.Sprintf("%-15s %s\n", "Groups:", strings.Join(groups, ", ")))
	result.WriteString(fmt.Sprintf("%-15s %t\n", "Is Admin:", isAdmin))

	// --- Account status (check if shell is nologin or false) ---
	accountStatus := "enabled"
	if strings.Contains(shell, "nologin") || strings.Contains(shell, "/false") {
		accountStatus = "disabled"
	}
	result.WriteString(fmt.Sprintf("%-15s %s\n", "Account Status:", accountStatus))

	// --- Last login via `last` command ---
	lastLogin := u.getLastLoginLinux(ctx, username)
	result.WriteString(fmt.Sprintf("%-15s %s\n", "Last Login:", lastLogin))

	// --- Full detail: additional info ---
	if detailLevel == "full" {
		result.WriteString("\n--- Extended Details ---\n")

		// Check password status via passwd -S.
		cmd := exec.CommandContext(ctx, "passwd", "-S", username)
		out, err := cmd.CombinedOutput()
		if err == nil {
			result.WriteString(fmt.Sprintf("%-15s %s\n", "Passwd Status:", strings.TrimSpace(string(out))))
		}

		// Check crontab.
		cmd = exec.CommandContext(ctx, "crontab", "-l", "-u", username)
		out, err = cmd.CombinedOutput()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			result.WriteString(fmt.Sprintf("%-15s %s\n", "Crontab:", strings.TrimSpace(string(out))))
		} else {
			result.WriteString(fmt.Sprintf("%-15s %s\n", "Crontab:", "none"))
		}

		// Check SSH authorized keys.
		authKeysPath := fmt.Sprintf("%s/.ssh/authorized_keys", home)
		if info, err := os.Stat(authKeysPath); err == nil {
			result.WriteString(fmt.Sprintf("%-15s found (%d bytes)\n", "SSH Auth Keys:", info.Size()))
		} else {
			result.WriteString(fmt.Sprintf("%-15s %s\n", "SSH Auth Keys:", "not found"))
		}
	}

	return result.String(), nil
}

// parsePasswd reads /etc/passwd and extracts fields for the given username.
func (u *UserInfoSkill) parsePasswd(username string) (uid, gid, home, shell string, found bool, err error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return "", "", "", "", false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		if fields[0] == username {
			return fields[2], fields[3], fields[5], fields[6], true, nil
		}
	}
	return "", "", "", "", false, scanner.Err()
}

// parseGroups reads /etc/group and returns all groups the username belongs to,
// and whether the user is in the sudo/wheel/root group.
func (u *UserInfoSkill) parseGroups(username string) (groups []string, isAdmin bool) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, false
	}
	defer f.Close()

	adminGroups := map[string]bool{"sudo": true, "wheel": true, "root": true, "admin": true}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		members := strings.Split(fields[3], ",")
		for _, m := range members {
			if strings.TrimSpace(m) == username {
				groups = append(groups, groupName)
				if adminGroups[groupName] {
					isAdmin = true
				}
				break
			}
		}
	}

	if len(groups) == 0 {
		groups = []string{"(none)"}
	}
	return groups, isAdmin
}

// getLastLoginLinux runs `last <username>` and returns the most recent login line.
func (u *UserInfoSkill) getLastLoginLinux(ctx context.Context, username string) string {
	cmd := exec.CommandContext(ctx, "last", "-1", username)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "unavailable"
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 && lines[0] != "" && !strings.HasPrefix(lines[0], "wtmp") {
		return strings.TrimSpace(lines[0])
	}
	return "never"
}

// executeWindows gathers user info via PowerShell cmdlets.
func (u *UserInfoSkill) executeWindows(ctx context.Context, username, detailLevel string) (string, error) {
	var psScript strings.Builder

	psScript.WriteString(fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
try {
    $user = Get-LocalUser -Name '%s'
} catch {
    Write-Output "ERROR: User '%s' not found"
    exit 1
}

Write-Output "User Info: $($user.Name)"
Write-Output ('=' * 50)
Write-Output "Username:       $($user.Name)"
Write-Output "SID:            $($user.SID)"
Write-Output "Enabled:        $($user.Enabled)"
Write-Output "Last Logon:     $($user.LastLogon)"
Write-Output "Description:    $($user.Description)"

$status = 'enabled'
if (-not $user.Enabled) { $status = 'disabled' }
if ($user.LockedOut) { $status = 'locked' }
Write-Output "Account Status: $status"

# Check admin group membership
$isAdmin = $false
try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    foreach ($member in $admins) {
        if ($member.Name -like "*\%s" -or $member.Name -eq '%s') {
            $isAdmin = $true
            break
        }
    }
} catch {}
Write-Output "Is Admin:       $isAdmin"

# Get all group memberships
$groups = @()
Get-LocalGroup | ForEach-Object {
    try {
        $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            if ($member.Name -like "*\%s" -or $member.Name -eq '%s') {
                $groups += $_.Name
                break
            }
        }
    } catch {}
}
Write-Output "Groups:         $($groups -join ', ')"
`, username, username, username, username, username, username))

	if detailLevel == "full" {
		psScript.WriteString(fmt.Sprintf(`
Write-Output ""
Write-Output "--- Extended Details ---"
Write-Output "Full Name:      $($user.FullName)"
Write-Output "Password Set:   $($user.PasswordLastSet)"
Write-Output "Pass Expires:   $($user.PasswordExpires)"
Write-Output "Pass Required:  $($user.PasswordRequired)"
Write-Output "Pass Changeable:$($user.UserMayChangePassword)"
Write-Output "Created:        $($user.ObjectClass)"

# Check for user profile path
$profilePath = "C:\Users\%s"
if (Test-Path $profilePath) {
    Write-Output "Profile Path:   $profilePath (exists)"
} else {
    Write-Output "Profile Path:   $profilePath (not found)"
}
`, username))
	}

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		output := string(out)
		if strings.Contains(output, "ERROR:") {
			return "", fmt.Errorf("%s", strings.TrimSpace(output))
		}
		return "", fmt.Errorf("PowerShell command failed: %w", err)
	}

	return string(out), nil
}
