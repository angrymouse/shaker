/*
 * Copyright (c) 2021 Sebastian Rasor <https://www.sebastianrasor.com/contact>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

const { Client, SQLiteProvider } = require('discord.js-commando');
const dns = require('dns');
const fetch = require('node-fetch');
const sqlite = require('sqlite')
const sqlite3 = require('sqlite3')
const uri = require('node-uri');

const dnsPromises = dns.promises;

dnsPromises.setServers(['127.0.0.1']);

const client = new Client({ intents: ['GUILD_MEMBERS', 'GUILDS'] });

client.setProvider(
    sqlite.open({ filename: 'database.db', driver: sqlite3.Database }).then(db => new SQLiteProvider(db))
).catch(console.error);

client.on('guildMemberAdd', member => {
	if (member.displayName.slice(-1) == '/') {
		var newName = member.displayName;
		if (newName.slice(-1) === '/') {
			newName = newName.replace(/\/+$/, '');
			if (newName === '') {
				newName = member.id
			}
		};
		member.setNickname(newName, 'Trailing slash display names are reserved for those who have verified.')
			.catch(console.error);
	};
});

var whitelist = [];
client.on('guildMemberUpdate', (oldMember, newMember) => {
	if (oldMember.displayName === newMember.displayName) {
		return;
	}

	if (whitelist.indexOf(newMember.id) === -1) {
		const role = newMember.guild.settings.get('verifiedRole');
		if (role) {
			newMember.roles.remove(role)
		}

		if (newMember.displayName.slice(-1) === '/')  {
			var newName = oldMember.displayName;
			if (newName.slice(-1) === '/') {
				newName = newName.replace(/\/+$/, '');
				if (newName === '') {
					newName = oldMember.id;
				}
			};
			newMember.setNickname(newName, 'Trailing slash display names are reserved for those who have verified.')
				.catch(console.error);
		}
	} else {
		whitelist = whitelist.filter(id => id !== newMember.id);
	};
});

client.on('interaction', async interaction => {
	if (!interaction.isCommand()) return;

	if (!interaction.guild) return interaction.reply('Shaker only works in guilds.', { ephemeral: true });

	if (interaction.commandName === 'setverifiedrole' ) {
		if (interaction.member.permissions.has('ADMINISTRATOR')) {
			interaction.guild.settings.set('verifiedRole', interaction.options[0].value);
			interaction.reply(`The verified role has been set to <@&${interaction.options[0].value}>.`, { ephemeral: true });
		} else {
			return interaction.reply('You must be a server administrator to use this command.', { ephemeral: true });
		}
	}

	if (interaction.commandName === 'setwelcomechannel' ) {
		if (interaction.member.permissions.has('ADMINISTRATOR')) {
			interaction.guild.settings.set('welcomeChannel', interaction.options[0].value);
			interaction.reply(`The welcome channel has been set to <@&${interaction.options[0].value}>.`, { ephemeral: true });
		} else {
			return interaction.reply('You must be a server administrator to use this command.', { ephemeral: true });
		}
	}

	if (interaction.commandName === 'setwelcomemessage' ) {
		if (interaction.member.permissions.has('ADMINISTRATOR')) {
			interaction.guild.settings.set('welcomeMessage', interaction.options[0].value);
			interaction.reply(`The welcome message has been set to <@&${interaction.options[0].value}>.`, { ephemeral: true });
		} else {
			return interaction.reply('You must be a server administrator to use this command.', { ephemeral: true });
		}
	}

	if (interaction.commandName === 'verify') {
		const input = interaction.options[0].value
		const domain = uri.punycode(input.replace(/\/+$/, ''));
		const hostnameParts = domain.split('.');
		const tld = hostnameParts[hostnameParts.length - 1]
		if (tld === '' || /^\d+$/.test(input)) {
			return interaction.reply('It looks like the domain you tried to verify is invalid.', { ephemeral: true });
		}

		const txt = await dnsPromises.resolveTxt(`_shaker._auth.${tld}`)
			.catch(err => {
				const regex = new RegExp(`queryTxt (ENOTFOUND|ENODATA) _shaker._auth.${tld}`)
				if (!regex.test(err.message)) {
					console.error(err);
				}
			});
		if (!(txt && txt.find(array => array.indexOf(interaction.member.id) >= 0))) {
			const records = [{
				type: 'TXT',
				host: '_shaker._auth',
				value: interaction.member.id,
				ttl: 60,
			}]

			return interaction.reply(`To verify that you own \`${tld}/\` please create a TXT record located at \`_shaker._auth.${tld}\` with the content: \`${interaction.member.id}\`\n\nIf you use Namebase, you can do that automatically be visiting the following link:\n<https://namebase.io/next/domain-manager/${tld}/records?records=${btoa(JSON.stringify(records))}>\n\nOnce the record is set, simply run \`/verify ${domain}\` again and your account will be verified!`, { ephemeral: true });
		}

		process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
		const response = await fetch(`http://${domain}/`)
			.catch(err => {
				if (err.message !== `request to http://${domain}/ failed, reason: getaddrinfo ENOTFOUND ${domain}`) {
					console.error(err);
				}
			});
		process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';

		if (!response) {
			return interaction.reply(`It looks like that name doesn't resolve. Is there content visible at <http://${domain}>?\nYou can find new ways to use your Handshake name at <https://www.namebase.io/use-cases>`, { ephemeral: true });
		}

		whitelist.push(interaction.member.id);
		interaction.member.setNickname(`${uri.punydecode(domain)}/`, 'User verified Handshake domain.')
			.then(() => {
				const role = interaction.guild.settings.get('verifiedRole');
				if (role) {
					interaction.member.roles.add(role);
				}

				const welcomeChannel = interaction.guild.settings.get('welcomeChannel');
				const welcomeMessage = interaction.guild.settings.get('welcomeMessage');
				if (welcomeChannel && welcomeMessage) {
					const fetchedLogs = interaction.guild.fetchAuditLogs({
						type: 'MEMBER_ROLE_UPDATE',
						user: client.user
					})

					const entry = fetchedLogs.entries.find(entry => entry.target.id === interaction.member.id);

					if (!entry) {
						const messageToSend = welcomeMessage.replace('$USER$', `<@${interaction.member.id}>`);
						welcomeChannel.send(messageToSend);
					}
				}


				console.log(`${interaction.user.tag} (${interaction.user.id}) verified as ${uri.punydecode(domain)}/`);
				return interaction.reply(`Your name was successfully verified! Your new nickname is: \`${uri.punydecode(domain)}/\``, { ephemeral: true });
			})
			.catch(err => {
				whitelist = whitelist.filter(id => id !== interaction.member.id);
				if (err.message === 'Missing Permissions') {
					if (interaction.member.id === interaction.guild.ownerID) {
						return interaction.reply('Shaker isn\'t allowed to set the server owner\'s nickname. There is no way to change this.', { ephemeral: true });
					}
					return interaction.reply('Shaker currently doesn\'t have permission to set your nickname on this server.', { ephemeral: true });
				}
				return console.error(err.message);
			});
	}
});

client.once('ready', () => {
	console.log(`Logged in as ${client.user.tag}! (${client.user.id})`);
});

client.on('error', console.error);

client.login();
