/**
 * Zenith Auth - Official Discord Bot Engine
 * Multi-application control, automated license vending, free trial panels,
 * and server administration suite.
 */

const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  StringSelectMenuBuilder,
  StringSelectMenuOptionBuilder,
  PermissionFlagsBits
} = require('discord.js');

const crypto = require('crypto');
const { db, generateKey, hashPassword, generateAppSecret } = require('./database');

// Active Bot State
let clientInstance = null;
let currentToken = null;
let botStatus = {
  online: false,
  connecting: false,
  user: null,
  ping: 0,
  servers: 0,
  error: null,
  startedAt: null
};

// Default styling
const EMBED_COLOR = 0x5865F2; // Discord Blurple
const SUCCESS_COLOR = 0x22C55E; // Green
const DANGER_COLOR = 0xEF4444; // Red
const GOLD_COLOR = 0xF59E0B; // Amber

/**
 * Build Slash Command Definitions matching Zenith Auth specification
 */
function buildSlashCommands() {
  const commands = [];

  // --- 👑 Bot Owner Commands ---

  // 1. /genaccesskey [app] [days]
  commands.push(
    new SlashCommandBuilder()
      .setName('genaccesskey')
      .setDescription('Generate ZENITH server license key (Dropdown)')
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
      .addIntegerOption(opt => opt.setName('days').setDescription('Duration in days (default: 30)').setRequired(false))
      .addStringOption(opt => opt.setName('note').setDescription('Optional reference note').setRequired(false))
  );

  // 2. /stopkeys key:<key>
  commands.push(
    new SlashCommandBuilder()
      .setName('stopkeys')
      .setDescription('Pause server access key')
      .addStringOption(opt => opt.setName('key').setDescription('License key to pause').setRequired(true))
  );

  // 3. /resume key:<key>
  commands.push(
    new SlashCommandBuilder()
      .setName('resume')
      .setDescription('Resume paused server access key')
      .addStringOption(opt => opt.setName('key').setDescription('License key to resume').setRequired(true))
  );

  // 4. /deleteaccesskey key:<key>
  commands.push(
    new SlashCommandBuilder()
      .setName('deleteaccesskey')
      .setDescription('Delete unused server access key')
      .addStringOption(opt => opt.setName('key').setDescription('License key to delete permanently').setRequired(true))
  );

  // 5. /deletealluser
  commands.push(
    new SlashCommandBuilder()
      .setName('deletealluser')
      .setDescription('Delete all customer accounts for an application')
      .addStringOption(opt =>
        opt.setName('confirm')
          .setDescription('Type CONFIRM to execute')
          .setRequired(true)
          .addChoices({ name: 'CONFIRM', value: 'CONFIRM' })
      )
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
  );

  // 6. /add-application name:<app>
  commands.push(
    new SlashCommandBuilder()
      .setName('add-application')
      .setDescription('Add new application to platform dropdown')
      .addStringOption(opt => opt.setName('name').setDescription('Application name').setRequired(true))
  );

  // 7. /listservers
  commands.push(
    new SlashCommandBuilder()
      .setName('listservers')
      .setDescription('View all authorized servers and guilds the bot is connected to')
  );

  // --- ⚙️ Server Owner / Admin Commands ---

  // 8. /modifybot
  commands.push(
    new SlashCommandBuilder()
      .setName('modifybot')
      .setDescription('Customize bot nickname & avatar for this server')
      .addStringOption(opt => opt.setName('nickname').setDescription('New bot nickname').setRequired(false))
      .addStringOption(opt => opt.setName('avatar_url').setDescription('Avatar image HTTPS URL').setRequired(false))
  );

  // 9. /verify key:<ZENITH-KEY> [channel] [role]
  commands.push(
    new SlashCommandBuilder()
      .setName('verify')
      .setDescription('Activate this server & bind channel with Zenith License')
      .addStringOption(opt => opt.setName('key').setDescription('Zenith Activation Key').setRequired(true))
      .addChannelOption(opt => opt.setName('channel').setDescription('Channel to bind').setRequired(false))
      .addRoleOption(opt => opt.setName('role').setDescription('Role to assign on verification').setRequired(false))
  );

  // 10. /setupkey [app] [role] [channel] [display_name]
  commands.push(
    new SlashCommandBuilder()
      .setName('setupkey')
      .setDescription('Bind channel to application')
      .addStringOption(opt => opt.setName('app').setDescription('Application to bind').setAutocomplete(true).setRequired(false))
      .addRoleOption(opt => opt.setName('role').setDescription('Authorized seller / vendor role').setRequired(false))
      .addChannelOption(opt => opt.setName('channel').setDescription('Channel to bind (default: current)').setRequired(false))
      .addStringOption(opt => opt.setName('display_name').setDescription('Custom display name for vending').setRequired(false))
  );

  // 11. /setrole role:<role> [channel]
  commands.push(
    new SlashCommandBuilder()
      .setName('setrole')
      .setDescription('Set or change required seller role anytime')
      .addRoleOption(opt => opt.setName('role').setDescription('Role required to vend/manage').setRequired(true))
      .addChannelOption(opt => opt.setName('channel').setDescription('Target channel (default: current)').setRequired(false))
  );

  // 12. /list-setups
  commands.push(
    new SlashCommandBuilder()
      .setName('list-setups')
      .setDescription('Manage and view active channel & application bindings')
  );

  // 13. /remove-setup
  commands.push(
    new SlashCommandBuilder()
      .setName('remove-setup')
      .setDescription('Remove a channel binding')
      .addChannelOption(opt => opt.setName('channel').setDescription('Channel to unbind (default: current)').setRequired(false))
  );

  // --- 🎁 Free Key / Trial System (Admin) ---

  // 14. /freepanel [app] [type] [days] [channel]
  commands.push(
    new SlashCommandBuilder()
      .setName('freepanel')
      .setDescription('Send Free Trial claim panel with buttons')
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
      .addStringOption(opt =>
        opt.setName('type')
          .setDescription('Claim type')
          .setRequired(false)
          .addChoices(
            { name: 'License Key Only', value: 'license' },
            { name: 'Username & Password Only', value: 'userpass' },
            { name: 'Both (User Choice)', value: 'both' }
          )
      )
      .addIntegerOption(opt => opt.setName('days').setDescription('Trial duration in days (default: 1)').setRequired(false))
      .addChannelOption(opt => opt.setName('channel').setDescription('Target channel').setRequired(false))
  );

  // 15. /freekey-toggle status:<enable/disable>
  commands.push(
    new SlashCommandBuilder()
      .setName('freekey-toggle')
      .setDescription('Enable or disable free trial claims')
      .addStringOption(opt =>
        opt.setName('status')
          .setDescription('Enable or disable')
          .setRequired(true)
          .addChoices(
            { name: 'Enable Claims', value: 'enable' },
            { name: 'Disable Claims', value: 'disable' }
          )
      )
  );

  // 16. /freekey-reset
  commands.push(
    new SlashCommandBuilder()
      .setName('freekey-reset')
      .setDescription('Reset all claims so users can claim free trials again')
  );

  // --- 🔑 User & License Management (Public Output) ---

  // 17. /create-user username:<user> days:<days> password:<pass> hwid:<true/false> [allowed_devices] [client-name] [app]
  commands.push(
    new SlashCommandBuilder()
      .setName('create-user')
      .setDescription('Create client user account')
      .addStringOption(opt => opt.setName('username').setDescription('Account username').setRequired(true))
      .addStringOption(opt => opt.setName('password').setDescription('Account password').setRequired(true))
      .addIntegerOption(opt => opt.setName('days').setDescription('Subscription days').setRequired(true))
      .addBooleanOption(opt => opt.setName('hwid').setDescription('Lock to first hardware device?').setRequired(true))
      .addIntegerOption(opt => opt.setName('allowed_devices').setDescription('Allowed concurrent devices (default: 1)').setRequired(false))
      .addStringOption(opt => opt.setName('client-name').setDescription('Client reference name').setRequired(false))
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
  );

  // 18. /create-license days:<days> level:<level> quantity:<amount> client-name:<name> [note]
  commands.push(
    new SlashCommandBuilder()
      .setName('create-license')
      .setDescription('Generate client license keys')
      .addIntegerOption(opt => opt.setName('days').setDescription('Duration in days').setRequired(true))
      .addIntegerOption(opt => opt.setName('level').setDescription('Subscription level (e.g. 1)').setRequired(true))
      .addIntegerOption(opt => opt.setName('quantity').setDescription('Quantity to generate (1 to 25)').setRequired(true))
      .addStringOption(opt => opt.setName('client-name').setDescription('Client name or buyer tag').setRequired(false))
      .addStringOption(opt => opt.setName('note').setDescription('Custom license note').setRequired(false))
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
  );

  // 19. /hwid-reset username:<user>
  commands.push(
    new SlashCommandBuilder()
      .setName('hwid-reset')
      .setDescription('Reset user HWID binding')
      .addStringOption(opt => opt.setName('username').setDescription('Username to reset HWID for').setRequired(true))
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
  );

  // 20. /delete-user username:<user>
  commands.push(
    new SlashCommandBuilder()
      .setName('delete-user')
      .setDescription('Delete specific user account')
      .addStringOption(opt => opt.setName('username').setDescription('Username to delete').setRequired(true))
      .addStringOption(opt => opt.setName('app').setDescription('Target application').setAutocomplete(true).setRequired(false))
  );

  // 21. /delete-license key:<key>
  commands.push(
    new SlashCommandBuilder()
      .setName('delete-license')
      .setDescription('Delete specific license key')
      .addStringOption(opt => opt.setName('key').setDescription('License key to delete').setRequired(true))
  );

  // 22. /ping
  commands.push(
    new SlashCommandBuilder()
      .setName('ping')
      .setDescription('Check bot latency, uptime, and database status')
  );

  // 23. /help
  commands.push(
    new SlashCommandBuilder()
      .setName('help')
      .setDescription('View all Zenith Auth Bot Commands (Full Command List)')
  );

  // 24. /selectapp
  commands.push(
    new SlashCommandBuilder()
      .setName('selectapp')
      .setDescription('Switch active application dropdown for this channel or server')
      .addStringOption(opt => opt.setName('app').setDescription('Application name or ID').setAutocomplete(true).setRequired(false))
  );

  return commands;
}

/**
 * Retrieve User ID of the dashboard owner who configured the bot
 */
function getBotOwnerUserId() {
  try {
    const row = db.prepare("SELECT user_id FROM integrations WHERE type = 'discord_bot' AND user_id IS NOT NULL ORDER BY id DESC LIMIT 1").get();
    if (row && row.user_id) return row.user_id;
  } catch {}

  try {
    const owner = db.prepare("SELECT id FROM users WHERE username = 'ZEESHAN1017' OR role = 'Owner' OR role = 'Administrator' ORDER BY id ASC LIMIT 1").get();
    if (owner && owner.id) return owner.id;
  } catch {}

  return 8; // Default to ZEESHAN1017 master account
}

/**
 * Fetch available applications strictly isolated to the bot owner's account,
 * filtering out dummy/internal test applications.
 */
function getAvailableApplications() {
  const ownerUserId = getBotOwnerUserId();
  let apps = [];
  try {
    apps = db.prepare("SELECT id, name, version, status, owner_id FROM applications WHERE user_id = ? AND name NOT LIKE 'Default App%' ORDER BY id ASC").all(ownerUserId);
  } catch (err) {
    console.error('[Zenith Discord Bot] Error loading apps for owner user:', err.message);
  }

  // If user currently has no named apps, query non-default active apps across system
  if (!apps || apps.length === 0) {
    try {
      apps = db.prepare("SELECT id, name, version, status, owner_id FROM applications WHERE name NOT LIKE 'Default App%' ORDER BY id ASC").all();
    } catch {}
  }

  // Fallback to user's apps even if default
  if (!apps || apps.length === 0) {
    try {
      apps = db.prepare("SELECT id, name, version, status, owner_id FROM applications WHERE user_id = ? ORDER BY id ASC").all(ownerUserId);
    } catch {}
  }

  return apps || [];
}

/**
 * Resolve target application for a command
 */
function resolveApplication(appParam, guildId, channelId) {
  const ownerUserId = getBotOwnerUserId();

  // 1. Direct param (by numeric ID or by Name)
  if (appParam) {
    const numId = parseInt(appParam, 10);
    if (!isNaN(numId)) {
      const byId = db.prepare('SELECT * FROM applications WHERE id = ?').get(numId);
      if (byId) return byId;
    }
    const byName = db.prepare("SELECT * FROM applications WHERE lower(name) = lower(?) AND name NOT LIKE 'Default App%'").get(appParam);
    if (byName) return byName;
  }

  // 2. Channel or Guild binding
  if (channelId) {
    const bind = db.prepare('SELECT app_id FROM bot_bindings WHERE channel_id = ?').get(channelId);
    if (bind) {
      const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(bind.app_id);
      if (app) return app;
    }
  }
  if (guildId) {
    const bind = db.prepare('SELECT app_id FROM bot_bindings WHERE guild_id = ? ORDER BY id DESC LIMIT 1').get(guildId);
    if (bind) {
      const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(bind.app_id);
      if (app) return app;
    }
  }

  // 3. Fallback to owner's first active application
  const ownerApp = db.prepare("SELECT * FROM applications WHERE user_id = ? AND status = 'active' AND name NOT LIKE 'Default App%' ORDER BY id ASC LIMIT 1").get(ownerUserId);
  if (ownerApp) return ownerApp;

  // 4. Any application belonging to the bot owner
  const anyOwnerApp = db.prepare("SELECT * FROM applications WHERE user_id = ? AND name NOT LIKE 'Default App%' ORDER BY id ASC LIMIT 1").get(ownerUserId);
  if (anyOwnerApp) return anyOwnerApp;

  // 5. Global non-default fallback
  const globalApp = db.prepare("SELECT * FROM applications WHERE name NOT LIKE 'Default App%' ORDER BY id ASC LIMIT 1").get();
  if (globalApp) return globalApp;

  return db.prepare("SELECT * FROM applications ORDER BY id ASC LIMIT 1").get();
}

/**
 * Start the Discord Bot instance
 */
async function startBot(token, clientId = null) {
  if (botStatus.online && clientInstance) {
    return { success: true, message: 'Discord Bot is already running online.', status: getBotStatus() };
  }

  const cleanToken = (token || '').trim();
  if (!cleanToken) {
    return { success: false, message: 'Discord Bot Token is empty. Please enter a valid token.', status: getBotStatus() };
  }

  botStatus.connecting = true;
  botStatus.error = null;
  currentToken = cleanToken;

  try {
    if (clientInstance) {
      try { clientInstance.destroy(); } catch {}
      clientInstance = null;
    }

    const client = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
      ]
    });

    client.on('ready', async () => {
      botStatus.online = true;
      botStatus.connecting = false;
      botStatus.user = {
        tag: client.user.tag,
        id: client.user.id,
        avatar: client.user.displayAvatarURL()
      };
      botStatus.ping = client.ws.ping;
      botStatus.servers = client.guilds.cache.size;
      botStatus.error = null;
      botStatus.startedAt = new Date().toISOString();

      console.log(`[Zenith Discord Bot] Logged in successfully as ${client.user.tag} (ID: ${client.user.id})`);

      // Update database status
      try {
        db.prepare(`UPDATE integrations SET status = 'online', bot_username = ?, last_error = '', updated_at = datetime('now') WHERE type = 'discord_bot'`).run(client.user.tag);
      } catch {}

      // Register Slash Commands globally
      try {
        const rest = new REST({ version: '10' }).setToken(cleanToken);
        const commands = buildSlashCommands().map(c => c.toJSON());
        const targetId = clientId || client.user.id;

        console.log(`[Zenith Discord Bot] Registering ${commands.length} application (/) commands...`);
        await rest.put(Routes.applicationCommands(targetId), { body: commands });
        console.log(`[Zenith Discord Bot] Successfully registered all ${commands.length} application commands!`);
      } catch (cmdErr) {
        console.error('[Zenith Discord Bot] Error registering application commands:', cmdErr.message);
      }
    });

    client.on('error', (err) => {
      console.error('[Zenith Discord Bot] Client error:', err);
      botStatus.error = err.message;
      try {
        db.prepare(`UPDATE integrations SET last_error = ?, updated_at = datetime('now') WHERE type = 'discord_bot'`).run(err.message);
      } catch {}
    });

    client.on('disconnect', () => {
      botStatus.online = false;
      botStatus.connecting = false;
      console.log('[Zenith Discord Bot] Client disconnected.');
    });

    // Handle Autocomplete Interactions
    client.on('interactionCreate', async (interaction) => {
      try {
        if (interaction.isAutocomplete()) {
          const focused = interaction.options.getFocused(true);
          if (focused.name === 'app') {
            const apps = getAvailableApplications();
            const filterVal = (focused.value || '').toLowerCase();
            const filtered = apps.filter(a => a.name.toLowerCase().includes(filterVal) || String(a.id).includes(filterVal));
            const choices = filtered.map(a => ({ name: `${a.name} (ID: ${a.id})`, value: String(a.id) }));
            await interaction.respond(choices.slice(0, 25));
          }
          return;
        }

        // Handle Button Interactions (Free Trial Panel)
        if (interaction.isButton()) {
          await handleButtonInteraction(interaction);
          return;
        }

        // Handle Select Menu Interactions (Select Application)
        if (interaction.isStringSelectMenu()) {
          await handleSelectMenuInteraction(interaction);
          return;
        }

        // Handle Slash Commands
        if (interaction.isChatInputCommand()) {
          await handleSlashCommand(interaction);
          return;
        }
      } catch (interErr) {
        console.error('[Zenith Discord Bot] Interaction error:', interErr);
        if (!interaction.replied && !interaction.deferred) {
          await interaction.reply({ content: `❌ Error processing request: ${interErr.message}`, ephemeral: true }).catch(() => {});
        }
      }
    });

    clientInstance = client;
    await client.login(cleanToken);

    return {
      success: true,
      message: 'Discord Bot login initiated successfully.',
      status: getBotStatus()
    };
  } catch (err) {
    botStatus.online = false;
    botStatus.connecting = false;
    botStatus.error = err.message;
    console.error('[Zenith Discord Bot] Login failed:', err.message);

    try {
      db.prepare(`UPDATE integrations SET status = 'error', last_error = ?, updated_at = datetime('now') WHERE type = 'discord_bot'`).run(err.message);
    } catch {}

    return {
      success: false,
      message: `Failed to connect Discord Bot: ${err.message}`,
      status: getBotStatus()
    };
  }
}

/**
 * Stop the Discord Bot
 */
function stopBot() {
  if (clientInstance) {
    try {
      clientInstance.destroy();
    } catch {}
    clientInstance = null;
  }
  botStatus.online = false;
  botStatus.connecting = false;
  botStatus.user = null;
  botStatus.error = null;

  try {
    db.prepare(`UPDATE integrations SET status = 'offline', updated_at = datetime('now') WHERE type = 'discord_bot'`).run();
  } catch {}

  console.log('[Zenith Discord Bot] Bot stopped by administrator.');
  return { success: true, message: 'Discord Bot disconnected.', status: getBotStatus() };
}

/**
 * Get live bot status
 */
function getBotStatus() {
  return {
    online: botStatus.online,
    connecting: botStatus.connecting,
    user: botStatus.user,
    ping: clientInstance && clientInstance.ws ? clientInstance.ws.ping : 0,
    servers: clientInstance && clientInstance.guilds ? clientInstance.guilds.cache.size : 0,
    error: botStatus.error,
    startedAt: botStatus.startedAt
  };
}

/**
 * Auto-start Discord bot if enabled in database
 */
async function autoStartIfConfigured() {
  try {
    const item = db.prepare(`SELECT * FROM integrations WHERE type = 'discord_bot' ORDER BY id DESC LIMIT 1`).get();
    if (item && item.enabled && item.bot_token && item.bot_token.trim().length > 10) {
      console.log('[Zenith Discord Bot] Auto-starting configured Discord Bot...');
      await startBot(item.bot_token, item.client_id);
    }
  } catch (err) {
    console.error('[Zenith Discord Bot] Auto-start check failed:', err.message);
  }
}

/**
 * Button Handler for Free Key / Free User Panel
 */
async function handleButtonInteraction(interaction) {
  const { customId, guildId, user } = interaction;

  // Check if claims are enabled
  const toggle = db.prepare(`SELECT value FROM bot_settings WHERE key = 'freekey_enabled'`).get();
  if (toggle && toggle.value === '0') {
    return interaction.reply({
      content: '❌ **Free Trial Claims are currently disabled by the server administrator.**',
      ephemeral: true
    });
  }

  const parts = customId.split('_');
  const action = parts[0] + '_' + parts[1]; // claim_license or claim_user
  const appId = parseInt(parts[2] || '1', 10);
  const days = parseInt(parts[3] || '1', 10);

  const targetApp = db.prepare('SELECT * FROM applications WHERE id = ?').get(appId) || { name: 'Zenith Application', id: 1 };

  // Check if user already claimed
  const existingClaim = db.prepare('SELECT * FROM bot_free_claims WHERE guild_id = ? AND discord_user_id = ? AND app_id = ?').get(guildId || 'DM', user.id, appId);
  if (existingClaim) {
    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('⚠️ Free Trial Already Claimed')
          .setDescription(`You have already claimed a free trial for **${targetApp.name}**!\n\n**Claimed On:** \`${existingClaim.claimed_at}\`\n**Key:** \`${existingClaim.claimed_key || 'Standard User'}\``)
          .setFooter({ text: 'Zenith Auth • Free Trial Policy' })
      ],
      ephemeral: true
    });
  }

  // 1. Claim Free License Key
  if (action === 'claim_license') {
    const key = generateKey('FREE', 16);
    let plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? ORDER BY id ASC LIMIT 1').get(targetApp.id);
    if (!plan) {
      const pi = db.prepare("INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status) VALUES (?, 'Trial Plan', 1, 30, 'Trial access plan', 0.00, 'active')").run(targetApp.id);
      plan = { id: pi.lastInsertRowid };
    }

    db.prepare(`
      INSERT INTO licenses (app_id, plan_id, license_key, length, duration_days, hwid_bound, activation_limit, status, created_by)
      VALUES (?, ?, ?, 16, ?, 1, 1, 'unused', ?)
    `).run(targetApp.id, plan.id, key, days, `Discord:${user.tag}`);

    db.prepare(`
      INSERT INTO bot_free_claims (guild_id, discord_user_id, discord_username, app_id, claim_type, claimed_key)
      VALUES (?, ?, ?, ?, 'license', ?)
    `).run(guildId || 'DM', user.id, user.tag, targetApp.id, key);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🎁 Free Trial License Generated!')
          .setDescription(`Here is your free activation license for **${targetApp.name}**.\n\nUse this key directly inside the client software.`)
          .addFields(
            { name: '🔑 License Key', value: `\`\`\`${key}\`\`\`` },
            { name: '⏱️ Duration', value: `${days} Day(s)`, inline: true },
            { name: '📱 Application', value: targetApp.name, inline: true }
          )
          .setFooter({ text: 'Keep this private. Key can only be activated once.' })
      ],
      ephemeral: true
    });
  }

  // 2. Claim Free User/Pass Account
  if (action === 'claim_user') {
    const cleanUsername = `usr_${user.username.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8)}_${crypto.randomBytes(2).toString('hex')}`;
    const cleanPassword = `Zenith@${crypto.randomBytes(3).toString('hex')}`;
    const pHash = hashPassword(cleanPassword);
    const expiry = new Date(Date.now() + days * 86400000).toISOString().split('T')[0];

    let plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? ORDER BY id ASC LIMIT 1').get(targetApp.id);
    if (!plan) {
      const pi = db.prepare("INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status) VALUES (?, 'Trial Plan', 1, 30, 'Trial access plan', 0.00, 'active')").run(targetApp.id);
      plan = { id: pi.lastInsertRowid };
    }

    db.prepare(`
      INSERT INTO app_users (app_id, username, password_hash, email, subscription_name, plan_id, expiry_date, hwid, hwid_lock, allowed_devices, status)
      VALUES (?, ?, ?, ?, 'Free Trial', ?, ?, '', 1, 1, 'active')
    `).run(targetApp.id, cleanUsername, pHash, `${cleanUsername}@trial.local`, plan.id, expiry);

    db.prepare(`
      INSERT INTO bot_free_claims (guild_id, discord_user_id, discord_username, app_id, claim_type, claimed_key)
      VALUES (?, ?, ?, ?, 'userpass', ?)
    `).run(guildId || 'DM', user.id, user.tag, targetApp.id, cleanUsername);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('👤 Free Trial Account Created!')
          .setDescription(`Your credentials for **${targetApp.name}** have been generated.`)
          .addFields(
            { name: '👤 Username', value: `\`\`\`${cleanUsername}\`\`\``, inline: true },
            { name: '🔒 Password', value: `\`\`\`${cleanPassword}\`\`\``, inline: true },
            { name: '📅 Expires On', value: `\`${expiry}\``, inline: false }
          )
          .setFooter({ text: 'Bind your HWID upon first client login.' })
      ],
      ephemeral: true
    });
  }
}

/**
 * Handle Application Selection Menu Interaction
 */
async function handleSelectMenuInteraction(interaction) {
  if (interaction.customId === 'select_active_app') {
    const selectedAppId = parseInt(interaction.values[0], 10);
    const app = db.prepare('SELECT * FROM applications WHERE id = ?').get(selectedAppId);
    if (!app) {
      return interaction.reply({ content: '❌ Selected application not found.', ephemeral: true });
    }

    // Bind this application to the current channel
    const existing = db.prepare('SELECT id FROM bot_bindings WHERE channel_id = ?').get(interaction.channelId);
    if (existing) {
      db.prepare('UPDATE bot_bindings SET app_id = ? WHERE id = ?').run(app.id, existing.id);
    } else {
      db.prepare(`
        INSERT INTO bot_bindings (guild_id, channel_id, app_id, display_name)
        VALUES (?, ?, ?, ?)
      `).run(interaction.guildId || 'DM', interaction.channelId, app.id, app.name);
    }

    return interaction.update({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🔄 Active Application Switched')
          .setDescription(`Channel <#${interaction.channelId}> is now linked to **${app.name}** (v${app.version || '1.0'}).\n\nAll subsequent vends, user creations, and commands in this channel will default to this application.`)
          .addFields(
            { name: 'App ID', value: String(app.id), inline: true },
            { name: 'Status', value: app.status || 'active', inline: true },
            { name: 'HWID Lock', value: app.hwid_lock ? 'Enabled' : 'Disabled', inline: true }
          )
          .setFooter({ text: 'Zenith Auth • Multi-App Routing' })
      ],
      components: []
    });
  }
}

/**
 * Main Slash Commands Router
 */
async function handleSlashCommand(interaction) {
  const { commandName, options, guildId, channelId, user, guild } = interaction;

  // --- 1. /help ---
  if (commandName === 'help') {
    const helpEmbed = new EmbedBuilder()
      .setColor(EMBED_COLOR)
      .setTitle('🛡️ ZENITH Auth Bot Commands')
      .setDescription(
        '**👑 Bot Owner Commands:**\n' +
        '`/genaccesskey [app] [days]` — Generate ZENITH server license key (Dropdown)\n' +
        '`/stopkeys key:<key>` — Pause server access key\n' +
        '`/resume key:<key>` — Resume paused server access key\n' +
        '`/deleteaccesskey key:<key>` — Delete unused server access key\n' +
        '`/deletealluser` — Delete all customer accounts\n' +
        '`/add-application name:<app>` — Add new app to dropdown\n' +
        '`/listservers` — View all authorized servers\n\n' +

        '**⚙️ Server Owner / Admin Commands:**\n' +
        '`/modifybot` — Customize bot nickname, avatar & banner for this server\n' +
        '`/verify key:<ZENITH-KEY> [channel] [role]` — Activate this server & bind channel\n' +
        '`/setupkey [app] [role] [channel] [display_name]` — Bind channel to application\n' +
        '`/setrole role:<role> [channel]` — Set/Change required seller role anytime\n' +
        '`/list-setups` / `/remove-setup` — Manage channel bindings\n\n' +

        '**🎁 Free Key / Trial System (Admin):**\n' +
        '`/freepanel [app] [type] [days] [channel]` — Send Free Trial claim panel (License, User/Pass, or Both)\n' +
        '`/freekey-toggle status:<enable/disable>` — Enable or disable free key claims\n' +
        '`/freekey-reset` — Reset all claims so users can claim again\n\n' +

        '**🔑 User & License Management (Public Output):**\n' +
        '`/create-user username:<user> days:<days> password:<pass> hwid:<true/false> client-name:<name>`\n' +
        '`/create-license days:<days> level:<level> quantity:<amount> client-name:<name> [note]`\n' +
        '`/hwid-reset username:<user>` — Reset user HWID\n' +
        '`/delete-user username:<user>` — Delete specific user account\n' +
        '`/delete-license key:<key>` — Delete specific license key\n' +
        '`/selectapp` — Switch or view current active application\n' +
        '`/ping` — Check latency and operational uptime'
      )
      .setFooter({ text: 'Zenith Auth • Cloud Security Engine' });

    return interaction.reply({ embeds: [helpEmbed] });
  }

  // --- 2. /ping ---
  if (commandName === 'ping') {
    const wsPing = clientInstance ? clientInstance.ws.ping : 0;
    const appsCount = db.prepare('SELECT count(*) as c FROM applications').get().c;
    const usersCount = db.prepare('SELECT count(*) as c FROM app_users').get().c;
    const keysCount = db.prepare('SELECT count(*) as c FROM licenses').get().c;

    const pingEmbed = new EmbedBuilder()
      .setColor(SUCCESS_COLOR)
      .setTitle('🏓 Pong! Zenith Bot Online')
      .addFields(
        { name: '📡 Gateway Latency', value: `\`${wsPing}ms\``, inline: true },
        { name: '🖥️ Uptime', value: `<t:${Math.floor(Date.now() / 1000)}:R>`, inline: true },
        { name: '📊 Database', value: `\`SQLite WAL (Active)\``, inline: true },
        { name: '📱 Applications', value: `\`${appsCount}\``, inline: true },
        { name: '👥 Total End-Users', value: `\`${usersCount}\``, inline: true },
        { name: '🔑 Total Licenses', value: `\`${keysCount}\``, inline: true }
      )
      .setFooter({ text: 'Zenith Auth • 24/7 Cloud Daemon' });

    return interaction.reply({ embeds: [pingEmbed] });
  }

  // --- 3. /selectapp [app] ---
  if (commandName === 'selectapp') {
    const appArg = options.getString('app');
    if (appArg) {
      const app = resolveApplication(appArg, guildId, channelId);
      if (!app) return interaction.reply({ content: '❌ Application not found.', ephemeral: true });

      const existing = db.prepare('SELECT id FROM bot_bindings WHERE channel_id = ?').get(channelId);
      if (existing) {
        db.prepare('UPDATE bot_bindings SET app_id = ? WHERE id = ?').run(app.id, existing.id);
      } else {
        db.prepare(`INSERT INTO bot_bindings (guild_id, channel_id, app_id, display_name) VALUES (?, ?, ?, ?)`).run(guildId || 'DM', channelId, app.id, app.name);
      }

      return interaction.reply({
        embeds: [
          new EmbedBuilder()
            .setColor(SUCCESS_COLOR)
            .setTitle('🎯 Channel Bound to Application')
            .setDescription(`This channel has been successfully locked to **${app.name}** (ID: ${app.id}).`)
        ]
      });
    }

    // Show interactive select menu dropdown
    const allApps = getAvailableApplications();
    if (allApps.length === 0) {
      return interaction.reply({ content: '❌ No applications exist yet. Create one in dashboard or via `/add-application`.', ephemeral: true });
    }

    const selectMenu = new StringSelectMenuBuilder()
      .setCustomId('select_active_app')
      .setPlaceholder('Select an application from dropdown...')
      .addOptions(
        allApps.map(a =>
          new StringSelectMenuOptionBuilder()
            .setLabel(`${a.name} (v${a.version || '1.0'})`)
            .setDescription(`ID: ${a.id} • Status: ${a.status}`)
            .setValue(String(a.id))
        )
      );

    const row = new ActionRowBuilder().addComponents(selectMenu);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(EMBED_COLOR)
          .setTitle('📱 Zenith Auth - Application Selector')
          .setDescription('Choose which application this Discord channel should manage and vend for:')
      ],
      components: [row],
      ephemeral: true
    });
  }

  // --- 4. /genaccesskey [app] [days] ---
  if (commandName === 'genaccesskey') {
    const appArg = options.getString('app');
    const days = options.getInteger('days') || 30;
    const note = options.getString('note') || 'Generated via Discord Bot';

    const app = resolveApplication(appArg, guildId, channelId);
    if (!app) return interaction.reply({ content: '❌ No active application found.', ephemeral: true });

    const key = generateKey('ZENITH', 16);
    let plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? ORDER BY id ASC LIMIT 1').get(app.id);
    if (!plan) {
      const pi = db.prepare("INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status) VALUES (?, 'Server Plan', 1, 30, 'Server access plan', 19.99, 'active')").run(app.id);
      plan = { id: pi.lastInsertRowid };
    }

    db.prepare(`
      INSERT INTO licenses (app_id, plan_id, license_key, length, duration_days, hwid_bound, activation_limit, status, created_by)
      VALUES (?, ?, ?, 16, ?, 1, 1, 'unused', ?)
    `).run(app.id, plan.id, key, days, `Discord:${user.tag}`);

    const embed = new EmbedBuilder()
      .setColor(GOLD_COLOR)
      .setTitle('👑 ZENITH Server Access Key Generated')
      .setDescription(`New server access key generated for **${app.name}**.`)
      .addFields(
        { name: '🔑 License Key', value: `\`\`\`${key}\`\`\`` },
        { name: '⏱️ Duration', value: `${days} Days`, inline: true },
        { name: '📱 Application', value: `${app.name} (ID: ${app.id})`, inline: true },
        { name: '📝 Note', value: note, inline: true }
      )
      .setFooter({ text: `Generated by ${user.tag}` })
      .setTimestamp();

    return interaction.reply({ embeds: [embed] });
  }

  // --- 5. /stopkeys key:<key> ---
  if (commandName === 'stopkeys') {
    const key = options.getString('key').trim();
    const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);
    if (!lic) return interaction.reply({ content: `❌ License key \`${key}\` not found.`, ephemeral: true });

    db.prepare("UPDATE licenses SET status = 'revoked' WHERE id = ?").run(lic.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('⏸️ License Key Paused / Revoked')
          .setDescription(`Server access key \`${key}\` has been **paused/revoked**.\nClient authorizations using this key are now blocked.`)
          .setFooter({ text: `Action by ${user.tag}` })
      ]
    });
  }

  // --- 6. /resume key:<key> ---
  if (commandName === 'resume') {
    const key = options.getString('key').trim();
    const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);
    if (!lic) return interaction.reply({ content: `❌ License key \`${key}\` not found.`, ephemeral: true });

    db.prepare("UPDATE licenses SET status = 'active' WHERE id = ?").run(lic.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('▶️ License Key Resumed')
          .setDescription(`Server access key \`${key}\` has been **resumed/activated**.\nClients may now connect normally.`)
          .setFooter({ text: `Action by ${user.tag}` })
      ]
    });
  }

  // --- 7. /deleteaccesskey key:<key> ---
  if (commandName === 'deleteaccesskey') {
    const key = options.getString('key').trim();
    const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);
    if (!lic) return interaction.reply({ content: `❌ License key \`${key}\` not found.`, ephemeral: true });

    db.prepare('DELETE FROM licenses WHERE id = ?').run(lic.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('🗑️ License Key Deleted')
          .setDescription(`License key \`${key}\` has been **permanently deleted** from the database.`)
          .setFooter({ text: `Action by ${user.tag}` })
      ]
    });
  }

  // --- 8. /deletealluser ---
  if (commandName === 'deletealluser') {
    const appArg = options.getString('app');
    const app = resolveApplication(appArg, guildId, channelId);

    let count = 0;
    if (app) {
      count = db.prepare('SELECT count(*) as c FROM app_users WHERE app_id = ?').get(app.id).c;
      db.prepare('DELETE FROM app_users WHERE app_id = ?').run(app.id);
    } else {
      count = db.prepare('SELECT count(*) as c FROM app_users').get().c;
      db.prepare('DELETE FROM app_users').run();
    }

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('⚠️ All Customer Accounts Purged')
          .setDescription(`Successfully purged **${count}** customer user accounts${app ? ` for **${app.name}**` : ''}.`)
          .setFooter({ text: `Authorized by ${user.tag}` })
      ]
    });
  }

  // --- 9. /add-application name:<app> ---
  if (commandName === 'add-application') {
    const appName = options.getString('name').trim();
    const version = '1.0';

    const ownerUserId = getBotOwnerUserId();
    const ownerUser = db.prepare('SELECT id, username, email, owner_id FROM users WHERE id = ?').get(ownerUserId);
    const ownerId = (ownerUser && ownerUser.owner_id) ? ownerUser.owner_id : 'KI81RSL4JP';

    // Check if application with same name already exists for this owner
    const existing = db.prepare('SELECT id, name FROM applications WHERE user_id = ? AND lower(name) = lower(?)').get(ownerUserId, appName);
    if (existing) {
      return interaction.reply({
        content: `❌ Application **${appName}** already exists (ID: \`${existing.id}\`). Please specify a different name.`,
        ephemeral: true
      });
    }

    const secretKey = generateAppSecret();
    const publicKey = 'za_pub_' + crypto.randomBytes(12).toString('hex');

    const info = db.prepare(`
      INSERT INTO applications (name, version, status, secret_key, public_key, owner_id, user_id, description, hwid_lock, ip_lock, hash_check, max_sessions)
      VALUES (?, ?, 'active', ?, ?, ?, ?, 'Created via Discord Bot', 1, 0, 0, 1)
    `).run(appName, version, secretKey, publicKey, ownerId, ownerUserId);

    const newAppId = info.lastInsertRowid;

    // Create default application settings
    try {
      db.prepare(`
        INSERT INTO application_settings (app_id, webhook_url, webhook_events, token_validation, whitelist_enabled, blacklist_enabled, session_timeout)
        VALUES (?, '', 'login,register,license_activate', 1, 0, 1, 60)
      `).run(newAppId);
    } catch {}

    // Create default subscription plan (Required for foreign-key licenses & client accounts)
    try {
      db.prepare(`
        INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status)
        VALUES (?, 'Standard Plan', 1, 30, 'Initial plan created via Discord Bot', 19.99, 'active')
      `).run(newAppId);
    } catch {}

    // Create default chat channel
    try {
      db.prepare(`
        INSERT INTO chatrooms (app_id, name, topic, is_private)
        VALUES (?, 'general', 'General discussion channel', 0)
      `).run(newAppId);
    } catch {}

    // Auto-bind current channel to newly created application
    try {
      const bindExisting = db.prepare('SELECT id FROM bot_bindings WHERE channel_id = ?').get(channelId);
      if (bindExisting) {
        db.prepare('UPDATE bot_bindings SET app_id = ?, display_name = ? WHERE id = ?').run(newAppId, appName, bindExisting.id);
      } else {
        db.prepare('INSERT INTO bot_bindings (guild_id, channel_id, app_id, display_name) VALUES (?, ?, ?, ?)').run(guildId || 'DM', channelId, newAppId, appName);
      }
    } catch {}

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('✨ New Application Created Successfully')
          .setDescription(`Application **${appName}** has been initialized in Zenith Auth and assigned to account **${ownerUser ? ownerUser.username : 'Owner'}**.\nIt is now immediately active in the web dashboard and selectable in all bot dropdowns!`)
          .addFields(
            { name: '📱 Application Name', value: `**${appName}**`, inline: true },
            { name: '🔑 Owner ID', value: `\`${ownerId}\``, inline: true },
            { name: '🆔 App ID', value: `\`${newAppId}\``, inline: true },
            { name: '🏷️ Version', value: `\`${version}\``, inline: true },
            { name: '👑 Account Owner', value: `\`${ownerUser ? ownerUser.username : 'Owner'} (ID: ${ownerUserId})\``, inline: true },
            { name: '🌐 Public Key', value: `\`${publicKey}\``, inline: false },
            { name: '🔒 Secret Key (App Secret)', value: `\`${secretKey}\``, inline: false }
          )
          .setFooter({ text: `Created by ${user.tag} • Multi-App Synchronized` })
          .setTimestamp()
      ]
    });
  }

  // --- 10. /listservers ---
  if (commandName === 'listservers') {
    if (!clientInstance) return interaction.reply({ content: '❌ Bot is offline.', ephemeral: true });

    const guilds = clientInstance.guilds.cache.map(g => `• **${g.name}** (ID: \`${g.id}\` • \`${g.memberCount}\` members)`);
    const serverList = guilds.length > 0 ? guilds.slice(0, 25).join('\n') : 'No servers connected.';

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(EMBED_COLOR)
          .setTitle('🌐 Authorized Servers / Guilds')
          .setDescription(`Connected to **${clientInstance.guilds.cache.size}** Discord Server(s):\n\n${serverList}`)
          .setFooter({ text: 'Zenith Auth Multi-Server Mesh' })
      ]
    });
  }

  // --- 11. /modifybot ---
  if (commandName === 'modifybot') {
    const nickname = options.getString('nickname');
    const avatarUrl = options.getString('avatar_url');

    let responseMsg = 'Bot customization updated:';
    if (nickname && guild) {
      await guild.members.me.setNickname(nickname).catch(() => {});
      responseMsg += `\n• Nickname set to **${nickname}**`;
    }
    if (avatarUrl && clientInstance) {
      await clientInstance.user.setAvatar(avatarUrl).catch(e => {
        responseMsg += `\n• Avatar update failed: ${e.message}`;
      });
      responseMsg += `\n• Global Avatar updated`;
    }

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🎨 Bot Profile Modified')
          .setDescription(responseMsg)
      ],
      ephemeral: true
    });
  }

  // --- 12. /verify key:<ZENITH-KEY> [channel] [role] ---
  if (commandName === 'verify') {
    const key = options.getString('key').trim();
    const ch = options.getChannel('channel') || interaction.channel;
    const role = options.getRole('role');

    const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);
    if (!lic) {
      return interaction.reply({ content: '❌ Invalid Zenith license key provided.', ephemeral: true });
    }

    if (lic.status === 'revoked' || lic.status === 'expired') {
      return interaction.reply({ content: `❌ License key is ${lic.status}.`, ephemeral: true });
    }

    // Activate license
    db.prepare(`UPDATE licenses SET status = 'active', used_by = ? WHERE id = ?`).run(`Guild:${guild ? guild.name : guildId}`, lic.id);

    // Save binding
    db.prepare(`
      INSERT INTO bot_bindings (guild_id, channel_id, role_id, app_id, display_name)
      VALUES (?, ?, ?, ?, ?)
    `).run(guildId || 'DM', ch.id, role ? role.id : '', lic.app_id || 1, 'Verified Server');

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🛡️ Server Successfully Verified & Activated')
          .setDescription(`Guild **${guild ? guild.name : guildId}** is now officially authorized on Zenith Auth.`)
          .addFields(
            { name: 'Bound Channel', value: `<#${ch.id}>`, inline: true },
            { name: 'Assigned Role', value: role ? `<@&${role.id}>` : 'None', inline: true },
            { name: 'License Key', value: `\`${key}\`` }
          )
      ]
    });
  }

  // --- 13. /setupkey [app] [role] [channel] [display_name] ---
  if (commandName === 'setupkey') {
    const appArg = options.getString('app');
    const role = options.getRole('role');
    const ch = options.getChannel('channel') || interaction.channel;
    const displayName = options.getString('display_name') || 'Default Vendor';

    const app = resolveApplication(appArg, guildId, ch.id);
    if (!app) return interaction.reply({ content: '❌ No application found.', ephemeral: true });

    db.prepare(`
      INSERT INTO bot_bindings (guild_id, channel_id, role_id, app_id, display_name)
      VALUES (?, ?, ?, ?, ?)
    `).run(guildId || 'DM', ch.id, role ? role.id : '', app.id, displayName);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('⚙️ Channel Binding Configured')
          .setDescription(`Channel <#${ch.id}> is now configured to vend for **${app.name}**.`)
          .addFields(
            { name: 'Application', value: `${app.name} (ID: ${app.id})`, inline: true },
            { name: 'Vendor Role', value: role ? `<@&${role.id}>` : 'Open / Admin', inline: true },
            { name: 'Display Name', value: displayName, inline: true }
          )
      ]
    });
  }

  // --- 14. /setrole role:<role> [channel] ---
  if (commandName === 'setrole') {
    const role = options.getRole('role');
    const ch = options.getChannel('channel') || interaction.channel;

    const existing = db.prepare('SELECT id FROM bot_bindings WHERE channel_id = ?').get(ch.id);
    if (existing) {
      db.prepare('UPDATE bot_bindings SET role_id = ? WHERE id = ?').run(role.id, existing.id);
    } else {
      db.prepare('INSERT INTO bot_bindings (guild_id, channel_id, role_id, app_id) VALUES (?, ?, ?, 1)').run(guildId || 'DM', ch.id, role.id);
    }

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🛡️ Required Role Updated')
          .setDescription(`Seller/vendor commands in <#${ch.id}> now require role <@&${role.id}>.`)
      ]
    });
  }

  // --- 15. /list-setups ---
  if (commandName === 'list-setups') {
    const bindings = db.prepare('SELECT * FROM bot_bindings WHERE guild_id = ?').all(guildId || 'DM');
    if (bindings.length === 0) {
      return interaction.reply({ content: 'ℹ️ No channel bindings configured in this server. Use `/setupkey` to link a channel.', ephemeral: true });
    }

    const lines = bindings.map(b => {
      const app = db.prepare('SELECT name FROM applications WHERE id = ?').get(b.app_id);
      return `• ID: \`${b.id}\` | Channel: <#${b.channel_id}> | App: **${app ? app.name : 'ID ' + b.app_id}** | Role: ${b.role_id ? `<@&${b.role_id}>` : 'All'}`;
    });

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(EMBED_COLOR)
          .setTitle('📋 Active Channel Setups')
          .setDescription(lines.join('\n'))
      ]
    });
  }

  // --- 16. /remove-setup ---
  if (commandName === 'remove-setup') {
    const ch = options.getChannel('channel') || interaction.channel;
    db.prepare('DELETE FROM bot_bindings WHERE channel_id = ?').run(ch.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🗑️ Channel Binding Removed')
          .setDescription(`Binding for <#${ch.id}> has been removed.`)
      ]
    });
  }

  // --- 17. /freepanel [app] [type] [days] [channel] ---
  if (commandName === 'freepanel') {
    const appArg = options.getString('app');
    const claimType = options.getString('type') || 'both';
    const days = options.getInteger('days') || 1;
    const targetChannel = options.getChannel('channel') || interaction.channel;

    const app = resolveApplication(appArg, guildId, targetChannel.id);
    if (!app) return interaction.reply({ content: '❌ No application found.', ephemeral: true });

    const embed = new EmbedBuilder()
      .setColor(EMBED_COLOR)
      .setTitle(`🎁 ${app.name} — Free Trial Claim Panel`)
      .setDescription(
        `Experience the premium features of **${app.name}** for **${days} Day(s)** free of charge!\n\n` +
        `Click the button below to instantly receive your private credentials.`
      )
      .addFields(
        { name: '⏱️ Duration', value: `\`${days} Day(s)\``, inline: true },
        { name: '🛡️ Protection', value: `\`Hardware Lock & Anti-Cheat\``, inline: true }
      )
      .setFooter({ text: 'One claim per Discord user. Credentials delivered in private message.' });

    const row = new ActionRowBuilder();
    if (claimType === 'license' || claimType === 'both') {
      row.addComponents(
        new ButtonBuilder()
          .setCustomId(`claim_license_${app.id}_${days}`)
          .setLabel('🔑 Claim Free License Key')
          .setStyle(ButtonStyle.Success)
      );
    }
    if (claimType === 'userpass' || claimType === 'both') {
      row.addComponents(
        new ButtonBuilder()
          .setCustomId(`claim_user_${app.id}_${days}`)
          .setLabel('👤 Claim Free Account (User/Pass)')
          .setStyle(ButtonStyle.Primary)
      );
    }

    await targetChannel.send({ embeds: [embed], components: [row] });

    return interaction.reply({
      content: `✅ Free Trial Panel successfully dispatched to <#${targetChannel.id}>!`,
      ephemeral: true
    });
  }

  // --- 18. /freekey-toggle status:<enable/disable> ---
  if (commandName === 'freekey-toggle') {
    const status = options.getString('status');
    const enabled = status === 'enable' ? '1' : '0';

    db.prepare(`INSERT INTO bot_settings (key, value) VALUES ('freekey_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(enabled);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(status === 'enable' ? SUCCESS_COLOR : DANGER_COLOR)
          .setTitle(status === 'enable' ? '✅ Free Key Claims Enabled' : '⏸️ Free Key Claims Disabled')
          .setDescription(`Users **${status === 'enable' ? 'can now claim' : 'can no longer claim'}** free trial keys.`)
      ]
    });
  }

  // --- 19. /freekey-reset ---
  if (commandName === 'freekey-reset') {
    db.prepare('DELETE FROM bot_free_claims').run();

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(GOLD_COLOR)
          .setTitle('🔄 Free Trial Claims Reset')
          .setDescription('All previous user claims have been wiped. Users may now claim another free trial.')
      ]
    });
  }

  // --- 20. /create-user username:<user> days:<days> password:<pass> hwid:<true/false> [allowed_devices] [client-name] [app] ---
  if (commandName === 'create-user') {
    const username = options.getString('username').trim();
    const password = options.getString('password').trim();
    const days = options.getInteger('days');
    const hwidLock = options.getBoolean('hwid') ? 1 : 0;
    const allowedDevices = Math.max(1, options.getInteger('allowed_devices') || 1);
    const clientName = options.getString('client-name') || 'Customer';
    const appArg = options.getString('app');

    const app = resolveApplication(appArg, guildId, channelId);
    if (!app) return interaction.reply({ content: '❌ No application found.', ephemeral: true });

    const existing = db.prepare('SELECT id FROM app_users WHERE app_id = ? AND lower(username) = lower(?)').get(app.id, username);
    if (existing) {
      return interaction.reply({ content: `❌ Username \`${username}\` already exists in **${app.name}**. Choose a different username.`, ephemeral: true });
    }

    const pHash = hashPassword(password);
    const expiry = new Date(Date.now() + days * 86400000).toISOString().split('T')[0];

    // Find default or first plan for app
    let plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? ORDER BY id ASC LIMIT 1').get(app.id);
    if (!plan) {
      const pi = db.prepare("INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status) VALUES (?, 'Standard Plan', 1, 30, 'Standard plan', 19.99, 'active')").run(app.id);
      plan = { id: pi.lastInsertRowid };
    }

    db.prepare(`
      INSERT INTO app_users (app_id, username, password_hash, email, subscription_name, plan_id, expiry_date, hwid, hwid_lock, allowed_devices, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, 'active')
    `).run(app.id, username, pHash, `${username}@client.local`, `${days} Days Access`, plan.id, expiry, hwidLock, allowedDevices);

    const embed = new EmbedBuilder()
      .setColor(SUCCESS_COLOR)
      .setTitle('👤 Client User Account Created')
      .setDescription(`User account created successfully for **${app.name}**.`)
      .addFields(
        { name: '👤 Username', value: `\`${username}\``, inline: true },
        { name: '🔒 Password', value: `||${password}||`, inline: true },
        { name: '⏱️ Duration', value: `${days} Days`, inline: true },
        { name: '📅 Expiry Date', value: `\`${expiry}\``, inline: true },
        { name: '💻 HWID Binding', value: hwidLock ? '✅ Locked' : '❌ Open', inline: true },
        { name: '📱 Allowed Devices', value: `\`${allowedDevices}\``, inline: true },
        { name: '🏷️ Client Tag', value: clientName, inline: true },
        { name: '📱 Application', value: `${app.name} (ID: ${app.id})`, inline: true }
      )
      .setFooter({ text: `Issued by ${user.tag}` })
      .setTimestamp();

    return interaction.reply({ embeds: [embed] });
  }

  // --- 21. /create-license days:<days> level:<level> quantity:<amount> client-name:<name> [note] [app] ---
  if (commandName === 'create-license') {
    const days = options.getInteger('days');
    const level = options.getInteger('level');
    const quantity = Math.min(25, Math.max(1, options.getInteger('quantity')));
    const clientName = options.getString('client-name') || 'Customer';
    const note = options.getString('note') || 'Created via Discord Bot';
    const appArg = options.getString('app');

    const app = resolveApplication(appArg, guildId, channelId);
    if (!app) return interaction.reply({ content: '❌ No application found.', ephemeral: true });

    let plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? AND level = ? LIMIT 1').get(app.id, level);
    if (!plan) {
      plan = db.prepare('SELECT id FROM subscription_plans WHERE app_id = ? ORDER BY id ASC LIMIT 1').get(app.id);
    }
    if (!plan) {
      const pi = db.prepare("INSERT INTO subscription_plans (app_id, name, level, duration_days, description, price, status) VALUES (?, ?, ?, ?, ?, 19.99, 'active')").run(app.id, `Tier ${level} Plan`, level, days, 'Standard plan');
      plan = { id: pi.lastInsertRowid };
    }
    const targetPlanId = plan.id;

    const generated = [];
    for (let i = 0; i < quantity; i++) {
      const key = generateKey('ZENITH', 16);
      db.prepare(`
        INSERT INTO licenses (app_id, plan_id, license_key, length, duration_days, hwid_bound, activation_limit, status, created_by)
        VALUES (?, ?, ?, 16, ?, 1, 1, 'unused', ?)
      `).run(app.id, targetPlanId, key, days, `Discord:${user.tag} (${clientName})`);
      generated.push(key);
    }

    const keyList = generated.map(k => `\`${k}\``).join('\n');

    const embed = new EmbedBuilder()
      .setColor(GOLD_COLOR)
      .setTitle(`🔑 Generated ${quantity} License Key(s)`)
      .setDescription(`Application: **${app.name}**\nClient: **${clientName}**\n\n${keyList}`)
      .addFields(
        { name: '⏱️ Duration', value: `${days} Days`, inline: true },
        { name: '⭐ Level', value: `Tier ${level}`, inline: true },
        { name: '📝 Note', value: note, inline: true }
      )
      .setFooter({ text: `Dispensed by ${user.tag}` })
      .setTimestamp();

    return interaction.reply({ embeds: [embed] });
  }

  // --- 22. /hwid-reset username:<user> ---
  if (commandName === 'hwid-reset') {
    const username = options.getString('username').trim();
    const appArg = options.getString('app');
    const app = resolveApplication(appArg, guildId, channelId);

    const targetUser = db.prepare('SELECT * FROM app_users WHERE lower(username) = lower(?) AND app_id = ?').get(username, app.id);
    if (!targetUser) {
      return interaction.reply({ content: `❌ User \`${username}\` not found in **${app.name}**.`, ephemeral: true });
    }

    db.prepare("UPDATE app_users SET hwid = '' WHERE id = ?").run(targetUser.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(SUCCESS_COLOR)
          .setTitle('🔄 HWID Reset Successful')
          .setDescription(`Hardware ID lock has been removed for **${targetUser.username}**.\nTheir license will automatically bind to the next computer they log in with.`)
          .setFooter({ text: `Reset by ${user.tag}` })
      ]
    });
  }

  // --- 23. /delete-user username:<user> ---
  if (commandName === 'delete-user') {
    const username = options.getString('username').trim();
    const appArg = options.getString('app');
    const app = resolveApplication(appArg, guildId, channelId);

    const targetUser = db.prepare('SELECT * FROM app_users WHERE lower(username) = lower(?) AND app_id = ?').get(username, app.id);
    if (!targetUser) {
      return interaction.reply({ content: `❌ User \`${username}\` not found in **${app.name}**.`, ephemeral: true });
    }

    db.prepare('DELETE FROM app_users WHERE id = ?').run(targetUser.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('🗑️ User Account Deleted')
          .setDescription(`Account \`${username}\` has been permanently deleted from **${app.name}**.`)
          .setFooter({ text: `Deleted by ${user.tag}` })
      ]
    });
  }

  // --- 24. /delete-license key:<key> ---
  if (commandName === 'delete-license') {
    const key = options.getString('key').trim();
    const lic = db.prepare('SELECT * FROM licenses WHERE license_key = ?').get(key);
    if (!lic) return interaction.reply({ content: `❌ License key \`${key}\` not found.`, ephemeral: true });

    db.prepare('DELETE FROM licenses WHERE id = ?').run(lic.id);

    return interaction.reply({
      embeds: [
        new EmbedBuilder()
          .setColor(DANGER_COLOR)
          .setTitle('🗑️ License Key Deleted')
          .setDescription(`License key \`${key}\` has been permanently deleted.`)
          .setFooter({ text: `Deleted by ${user.tag}` })
      ]
    });
  }
}

module.exports = {
  startBot,
  stopBot,
  getBotStatus,
  autoStartIfConfigured,
  buildSlashCommands
};
