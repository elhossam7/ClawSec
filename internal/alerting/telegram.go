// Package alerting implements Telegram bot and alert channel integrations.
package alerting

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"github.com/elhossam7/SecClaw/internal/config"
	"github.com/elhossam7/SecClaw/internal/response"
	"github.com/elhossam7/SecClaw/internal/types"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// TelegramBot handles Telegram alerting and interactive approval.
type TelegramBot struct {
	bot          *tgbotapi.BotAPI
	cfg          config.TelegramConfig
	orchestrator *response.Orchestrator
	logger       zerolog.Logger
	mu           sync.Mutex
}

// NewTelegramBot creates and initializes a Telegram bot.
func NewTelegramBot(cfg config.TelegramConfig, orch *response.Orchestrator, logger zerolog.Logger) (*TelegramBot, error) {
	bot, err := tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		return nil, fmt.Errorf("creating telegram bot: %w", err)
	}

	logger.Info().Str("username", bot.Self.UserName).Msg("telegram bot initialized")

	return &TelegramBot{
		bot:          bot,
		cfg:          cfg,
		orchestrator: orch,
		logger:       logger.With().Str("component", "telegram").Logger(),
	}, nil
}

// Start begins listening for Telegram updates (commands and callbacks).
func (tb *TelegramBot) Start() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := tb.bot.GetUpdatesChan(u)

	for update := range updates {
		if update.CallbackQuery != nil {
			tb.handleCallback(update.CallbackQuery)
			continue
		}

		if update.Message == nil || !update.Message.IsCommand() {
			continue
		}

		if !tb.isAllowed(update.Message.Chat.ID) {
			tb.logger.Warn().Int64("chat_id", update.Message.Chat.ID).Msg("unauthorized telegram access attempt")
			continue
		}

		tb.handleCommand(update.Message)
	}
}

// Stop shuts down the bot.
func (tb *TelegramBot) Stop() {
	tb.bot.StopReceivingUpdates()
}

// SendAlert sends a formatted alert to all allowed chats.
func (tb *TelegramBot) SendAlert(action types.ResponseAction) {
	icon := tb.severityIcon(action.Severity)
	msg := fmt.Sprintf(
		"%s *%s Alert*\n\n"+
			"*Type:* `%s`\n"+
			"*Target:* `%s`\n"+
			"*Reason:* %s\n"+
			"*Rule:* `%s`\n"+
			"*Severity:* %s\n"+
			"*ID:* `%s`",
		icon,
		strings.ToUpper(action.Severity.String()),
		action.Type,
		action.Target,
		escapeMarkdown(action.Reason),
		action.RuleID,
		action.Severity.String(),
		action.ID,
	)

	// Create inline keyboard with approve/deny buttons.
	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Approve", "approve:"+action.ID),
			tgbotapi.NewInlineKeyboardButtonData("❌ Deny", "deny:"+action.ID),
		),
	)

	for _, chatID := range tb.cfg.AllowedChats {
		m := tgbotapi.NewMessage(chatID, msg)
		m.ParseMode = "Markdown"
		m.ReplyMarkup = keyboard

		if _, err := tb.bot.Send(m); err != nil {
			tb.logger.Error().Err(err).Int64("chat_id", chatID).Msg("failed to send telegram alert")
		}
	}
}

// SendExecutionNotice notifies about an executed action.
func (tb *TelegramBot) SendExecutionNotice(action types.ResponseAction) {
	msg := fmt.Sprintf(
		"⚡ *Action Executed*\n\n"+
			"*Type:* `%s`\n"+
			"*Target:* `%s`\n"+
			"*Approved by:* %s\n"+
			"*ID:* `%s`\n\n"+
			"_Use /rollback %s to undo_",
		action.Type, action.Target, action.ApprovedBy, action.ID, action.ID,
	)

	for _, chatID := range tb.cfg.AllowedChats {
		m := tgbotapi.NewMessage(chatID, msg)
		m.ParseMode = "Markdown"
		tb.bot.Send(m)
	}
}

// handleCommand processes bot commands.
func (tb *TelegramBot) handleCommand(msg *tgbotapi.Message) {
	switch msg.Command() {
	case "start", "help":
		tb.sendHelp(msg.Chat.ID)
	case "status":
		tb.sendStatus(msg.Chat.ID)
	case "pending":
		tb.sendPending(msg.Chat.ID)
	case "approve":
		tb.handleApproveCommand(msg)
	case "deny":
		tb.handleDenyCommand(msg)
	case "rollback":
		tb.handleRollbackCommand(msg)
	default:
		tb.sendMessage(msg.Chat.ID, "Unknown command. Use /help for available commands.")
	}
}

// handleCallback processes inline button callbacks.
func (tb *TelegramBot) handleCallback(callback *tgbotapi.CallbackQuery) {
	if !tb.isAllowed(callback.Message.Chat.ID) {
		return
	}

	parts := strings.SplitN(callback.Data, ":", 2)
	if len(parts) != 2 {
		return
	}

	action, actionID := parts[0], parts[1]
	actor := fmt.Sprintf("telegram:%s", callback.From.UserName)

	var err error
	var response string

	switch action {
	case "approve":
		err = tb.orchestrator.Approve(actionID, actor)
		response = "✅ Action approved and executing..."
	case "deny":
		err = tb.orchestrator.Deny(actionID, actor)
		response = "❌ Action denied."
	}

	if err != nil {
		response = fmt.Sprintf("⚠️ Error: %s", err.Error())
	}

	// Answer the callback.
	cb := tgbotapi.NewCallback(callback.ID, response)
	tb.bot.Request(cb)

	// Update the message to remove buttons.
	edit := tgbotapi.NewEditMessageText(
		callback.Message.Chat.ID,
		callback.Message.MessageID,
		callback.Message.Text+"\n\n"+response,
	)
	edit.ParseMode = "Markdown"
	tb.bot.Send(edit)
}

func (tb *TelegramBot) handleApproveCommand(msg *tgbotapi.Message) {
	actionID := strings.TrimSpace(msg.CommandArguments())
	if actionID == "" {
		tb.sendMessage(msg.Chat.ID, "Usage: /approve <action-id>")
		return
	}

	actor := fmt.Sprintf("telegram:%s", msg.From.UserName)
	if err := tb.orchestrator.Approve(actionID, actor); err != nil {
		tb.sendMessage(msg.Chat.ID, fmt.Sprintf("⚠️ Error: %s", err.Error()))
		return
	}
	tb.sendMessage(msg.Chat.ID, "✅ Action approved and executed.")
}

func (tb *TelegramBot) handleDenyCommand(msg *tgbotapi.Message) {
	actionID := strings.TrimSpace(msg.CommandArguments())
	if actionID == "" {
		tb.sendMessage(msg.Chat.ID, "Usage: /deny <action-id>")
		return
	}

	actor := fmt.Sprintf("telegram:%s", msg.From.UserName)
	if err := tb.orchestrator.Deny(actionID, actor); err != nil {
		tb.sendMessage(msg.Chat.ID, fmt.Sprintf("⚠️ Error: %s", err.Error()))
		return
	}
	tb.sendMessage(msg.Chat.ID, "❌ Action denied.")
}

func (tb *TelegramBot) handleRollbackCommand(msg *tgbotapi.Message) {
	actionID := strings.TrimSpace(msg.CommandArguments())
	if actionID == "" {
		tb.sendMessage(msg.Chat.ID, "Usage: /rollback <action-id>")
		return
	}

	if err := tb.orchestrator.Rollback(actionID); err != nil {
		tb.sendMessage(msg.Chat.ID, fmt.Sprintf("⚠️ Error: %s", err.Error()))
		return
	}
	tb.sendMessage(msg.Chat.ID, "↩️ Action rolled back successfully.")
}

func (tb *TelegramBot) sendHelp(chatID int64) {
	help := "🛡 *Sentinel Bot Commands*\n\n" +
		"/status - Show agent health\n" +
		"/pending - List pending actions\n" +
		"/approve <id> - Approve an action\n" +
		"/deny <id> - Deny an action\n" +
		"/rollback <id> - Rollback an executed action\n" +
		"/help - Show this help"
	tb.sendMarkdown(chatID, help)
}

func (tb *TelegramBot) sendStatus(chatID int64) {
	pending, _ := tb.orchestrator.GetPendingActions()
	msg := fmt.Sprintf(
		"🛡 *Sentinel Status*\n\n"+
			"*Pending Actions:* %d\n"+
			"*Agent:* Running",
		len(pending),
	)
	tb.sendMarkdown(chatID, msg)
}

func (tb *TelegramBot) sendPending(chatID int64) {
	actions, err := tb.orchestrator.GetPendingActions()
	if err != nil {
		tb.sendMessage(chatID, "Error fetching pending actions.")
		return
	}

	if len(actions) == 0 {
		tb.sendMessage(chatID, "✅ No pending actions.")
		return
	}

	var sb strings.Builder
	sb.WriteString("⏳ *Pending Actions*\n\n")
	for _, a := range actions {
		sb.WriteString(fmt.Sprintf("• `%s` — %s `%s` → `%s`\n", a.ID, a.Type, a.Target, a.Severity.String()))
	}
	tb.sendMarkdown(chatID, sb.String())
}

func (tb *TelegramBot) sendMessage(chatID int64, text string) {
	m := tgbotapi.NewMessage(chatID, text)
	tb.bot.Send(m)
}

func (tb *TelegramBot) sendMarkdown(chatID int64, text string) {
	m := tgbotapi.NewMessage(chatID, text)
	m.ParseMode = "Markdown"
	tb.bot.Send(m)
}

func (tb *TelegramBot) isAllowed(chatID int64) bool {
	for _, allowed := range tb.cfg.AllowedChats {
		if allowed == chatID {
			return true
		}
	}
	return false
}

func (tb *TelegramBot) severityIcon(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return "🔴"
	case types.SeverityHigh:
		return "🟠"
	case types.SeverityMedium:
		return "🟡"
	case types.SeverityLow:
		return "🟢"
	default:
		return "🔵"
	}
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"`", "\\`",
		"[", "\\[",
	)
	return replacer.Replace(s)
}
