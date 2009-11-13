/*
 * Copyright (c) 2009 Shane Mc Cormack
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.dmdirc.relay;

import com.dmdirc.parser.common.MyInfo;
import com.dmdirc.parser.interfaces.ChannelClientInfo;
import com.dmdirc.parser.interfaces.ChannelInfo;
import com.dmdirc.parser.interfaces.ClientInfo;
import com.dmdirc.parser.interfaces.Parser;
import com.dmdirc.parser.interfaces.StringConverter;
import com.dmdirc.parser.interfaces.callbacks.ChannelActionListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelJoinListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelKickListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelMessageListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelPartListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelTopicListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelQuitListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelNickChangeListener;
import com.dmdirc.parser.interfaces.callbacks.MotdEndListener;
import com.dmdirc.parser.interfaces.callbacks.ChannelUserModeChangeListener;
import com.dmdirc.parser.interfaces.callbacks.DataInListener;
import com.dmdirc.parser.interfaces.callbacks.DataOutListener;
import com.dmdirc.parser.interfaces.callbacks.PrivateMessageListener;
import com.dmdirc.parser.interfaces.callbacks.SocketCloseListener;
import com.dmdirc.parser.interfaces.callbacks.ServerErrorListener;
import com.dmdirc.parser.interfaces.callbacks.NickChangeListener;
import com.dmdirc.parser.interfaces.callbacks.QuitListener;
import com.dmdirc.parser.irc.IRCParser;
import com.dmdirc.parser.irc.ServerInfo;
import com.dmdirc.parser.irc.outputqueue.QueueHandler;
import com.dmdirc.parser.irc.outputqueue.SimpleRateLimitedQueueHandler;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author shane
 */
public class Main implements ChannelMessageListener, ChannelActionListener,
                             ChannelTopicListener, ChannelJoinListener,
                             ChannelQuitListener, ChannelNickChangeListener,
                             ChannelPartListener, ChannelKickListener,
                             DataInListener, PrivateMessageListener,
                             MotdEndListener, ChannelUserModeChangeListener,
                             SocketCloseListener, ServerErrorListener,
                             DataOutListener, NickChangeListener, QuitListener {
    /** List of known parsers. */
    final List<Parser> myParsers = new LinkedList<Parser>();

    /**
     * List of not-joined parsers. Parsers in this list won't spam the main
     * channel when reconnecting.
     * All parsers are added here untill they join the relay channel.
     */
    final List<Parser> invalidParsers = new LinkedList<Parser>();

    /** Mapping of parsers to authCommands. */
    final Map<Parser, String[]> authCommands = new HashMap<Parser, String[]>();

    /** Main Parser */
    Parser mainParser = null;

    /** Relayed Channel Name */
    final String relayChannelName = "#Channel";

    /** Welcome Message */
    final String[] welcomeMessage = new String[]{"Welcome to "+relayChannelName+", this channel is being relayed across multiple networks."};

    /** Wanted Nick */
    final String wantedNick = "RelayBot";

    /** Real Name */
    final String realName = "Relay Bot";

    /** Local IP Address */
    final String wantedIP = "";

    /** Any Channel OP can be admin? */
    final boolean publicAdmin = true;

    /** Any one can do !names */
    final boolean publicNames = true;

    /**
     * If a non-bot ! command is issued on a relayed channel, should we relay
     * it back to the main channel in a form other bots will understand?
     */
    final boolean relayCommands = true;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        new Main();
    }

    /**
     * Create a new Main!
     */
    public Main() {
        synchronized (this) {
            mainParser = newParser("irc.quakenet.org", 6667, "", new String[]{"PRIVMSG Q@CServe.quakenet.org :auth ... ...", "MODE $me -x"});
        }
        newParser("irc.chatspike.net", 6667, "", new String[]{"PRIVMSG NickServ :identify ...", "MODE $me -x"});
        newParser("irc.oftc.net", 6667, "", new String[]{"PRIVMSG NickServ :identify ...", "MODE $me -x"});
        newParser("irc.freenode.net", 6667, "", new String[]{"PRIVMSG NickServ :identify ...", "MODE $me -x"});
    }

    /**
     * Reconnect the given parser to its server after the given delay.
     * 
     * @param tParser parser to reconnect
     * @param delay delay to wait in microseconds
     */
    public void reconnectParser(final Parser tParser, final long delay) {
        synchronized (myParsers) {
            if (!myParsers.contains(tParser)) { return; }

            myParsers.remove(tParser);
        }

        final ServerInfo server = ((IRCParser)tParser).server;

        synchronized (this) {
            if (mainParser != tParser && !isInvalidParser(tParser)) {
                mainParser.sendMessage(relayChannelName, "Reconnecting to: "+server.getHost()+" ("+(delay / 1000)+" second delay)");
            }
        }

        try { Thread.sleep(delay); } catch (InterruptedException ex) { }

        final String[] authCmd = authCommands.remove(tParser);
        final Parser newParser = newParser(server.getHost(), server.getPort(), server.getPassword(), authCmd);

        synchronized (this) {
            if (mainParser == tParser) {
                mainParser = newParser;
            }
        }
    }


    /** {@inheritDoc} */
    @Override
    public void onServerError(final Parser tParser, final String sMessage) {
        reconnectParser(tParser, 30 * 1000);
    }

    /** {@inheritDoc} */
    @Override
    public void onSocketClosed(final Parser tParser) {
        reconnectParser(tParser, 5 * 1000);
    }

    /**
     * Create a new parser on the given server.
     *any
     * @param server Server to parse on.
     * @param port Port to connect to.
     * @param pass Password for server.
     * @param authCommand Command to run to auth on this network.
     * @return IRCParser that was created.
     */
    public Parser newParser(final String server, final int port, final String pass, final String[] authCommand) {
        final ServerInfo serverDetails = new ServerInfo(server, port, pass);
        final MyInfo myDetails = new MyInfo();
        myDetails.setNickname(wantedNick);
        myDetails.setAltNickname(wantedNick+"`");
        myDetails.setRealname(realName);
        myDetails.setUsername(wantedNick.toLowerCase());

        final Parser thisParser = new IRCParser(myDetails, serverDetails);

        synchronized (myParsers) { myParsers.add(thisParser); }
        synchronized (invalidParsers) { invalidParsers.add(thisParser); }

        authCommands.put(thisParser, authCommand);

        thisParser.getCallbackManager().addCallback(ChannelMessageListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelActionListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelTopicListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelJoinListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelPartListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelKickListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelQuitListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelNickChangeListener.class, this, relayChannelName);
        thisParser.getCallbackManager().addCallback(ChannelUserModeChangeListener.class, this, relayChannelName);
        
        thisParser.getCallbackManager().addCallback(DataInListener.class, this);
        thisParser.getCallbackManager().addCallback(MotdEndListener.class, this);
        thisParser.getCallbackManager().addCallback(PrivateMessageListener.class, this);
        thisParser.getCallbackManager().addCallback(SocketCloseListener.class, this);
        thisParser.getCallbackManager().addCallback(ServerErrorListener.class, this);
        thisParser.getCallbackManager().addCallback(NickChangeListener.class, this);
        thisParser.getCallbackManager().addCallback(QuitListener.class, this);

        thisParser.setBindIP(wantedIP);

        ((IRCParser)thisParser).getOutputQueue().setQueueFactory(SimpleRateLimitedQueueHandler.getFactory());

        System.out.println("Starting Parser: "+server);

        final Thread thread = new Thread(thisParser, "parser-"+server);
        thread.start();

        return thisParser;
    }

    /**
     * Retrieves the name of this server's network. The network name is
     * determined using the following rules:
     *
     *  1. If the server includes its network name in the 005 information, we
     *     use that
     *  2. If the server's name ends in biz, com, info, net or org, we use the
     *     second level domain (e.g., foo.com)
     *  3. If the server's name contains more than two dots, we drop everything
     *     up to and including the first part, and use the remainder
     *  4. In all other cases, we use the full server name
     *
     * @param parser The parser to use.
     * @return The name of this server's network
     */
    public String getNetworkName(final Parser parser) {
        if (parser == null) {
            return "";
        } else if (parser.getNetworkName().isEmpty()) {
            return getNetworkNameFromServer(parser, parser.getServerName());
        } else {
            return parser.getNetworkName();
        }
    }

    /**
     * Calculates a network name from the specified server name. This method
     * implements parts 2-4 of the procedure documented at getNetwork().
     *
     * @param parser The parser to use.
     * @param serverName The server name to parse
     * @return A network name for the specified server
     */
    protected static String getNetworkNameFromServer(final Parser parser, final String serverName) {
        final String[] parts = serverName.split("\\.");
        final String[] tlds = {"biz", "com", "info", "net", "org"};
        boolean isTLD = false;

        for (String tld : tlds) {
            if (serverName.endsWith("." + tld)) {
                isTLD = true;
            }
        }

        if (isTLD && parts.length > 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        } else if (parts.length > 2) {
            final StringBuilder network = new StringBuilder();

            for (int i = 1; i < parts.length; i++) {
                if (network.length() > 0) {
                    network.append('.');
                }

                network.append(parts[i]);
            }

            return network.toString();
        } else {
            return serverName;
        }
    }


    /**
     * Send the onConnect stuff for the given parser
     * 
     * @param tParser Parser to send onConnect stuff for.
     */
    public void sendOnConnect(final Parser tParser) {
        for (String command : authCommands.get(tParser)) {
            tParser.sendRawMessage(command.replace("$me", tParser.getLocalClient().getNickname()));
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onMOTDEnd(final Parser tParser, final boolean noMOTD, final String sData) {
        sendOnConnect(tParser);
        
        tParser.joinChannel(relayChannelName);
        synchronized (invalidParsers) { invalidParsers.remove(tParser); }

        final QueueHandler qh = ((IRCParser)tParser).getOutputQueue().getQueueHandler();
        if (qh instanceof SimpleRateLimitedQueueHandler) {
            final SimpleRateLimitedQueueHandler srlqh = (SimpleRateLimitedQueueHandler)qh;

            srlqh.setItems(1);
            srlqh.setLimitTime(1000);
            srlqh.setWaitTime(2000);
        }
    }

    /**
     * Get all the current parsers
     *
     * @return A list of all the current parsers.
     */
    private List<Parser> getParsers() {
        final List<Parser> list;
        synchronized (myParsers) {
            list = new LinkedList<Parser>(myParsers);
        }
        return list;
    }

    /**
     * Check if the given parser is the main parser.
     *
     * @param parser Parser to check
     * @return true if the given parser is the main Parser.
     */
    private boolean isMainParser(final Parser parser) {
        final boolean result;
        synchronized (this) {
            result = (parser == mainParser);
        }
        return result;
    }

    /**
     * Check if the given parser is an invalid parser.
     *
     * @param parser Parser to check
     * @return true if the given parser is an invalid Parser.
     */
    private boolean isInvalidParser(final Parser parser) {
        final boolean result;
        synchronized (invalidParsers) {
            result = invalidParsers.contains(parser);
        }
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelMessage(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient, final String sMessage, final String sHost) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        if (!handleCommand(tParser, sMessage, sHost, cChannelClient)) {
            for (Parser parser : getParsers()) {
                if (!parser.equals(tParser)) {
                    parser.sendMessage(cChannel.getName(), String.format("+<%s@%s> %s", cChannelClient.getClient().getNickname(), getNetworkName(tParser), sMessage));
                }
            }

            if (relayCommands && tParser != mainParser && sMessage.charAt(0) == '!') {
                mainParser.sendMessage(cChannel.getName(), sMessage);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelAction(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient, final String sMessage, final String sHost) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c6* %s@%s %s", CODE_COLOUR, cChannelClient.getClient().getNickname(), getNetworkName(tParser), sMessage));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelTopic(final Parser tParser, final ChannelInfo cChannel, final boolean bIsJoinTopic) {
        final String mainTopic;
        synchronized (this) {
            mainTopic = mainParser.getChannel(cChannel.getName()).getTopic();
        }
        
        if (isMainParser(tParser)) {
            for (Parser parser : getParsers()) {
                if (!parser.equals(tParser)) {
                    System.out.println("Setting topic on "+getNetworkName(parser)+": "+mainTopic);
                    parser.getChannel(cChannel.getName()).setTopic(mainTopic);
                }
            }
        } else {
            if (!tParser.getStringConverter().equalsIgnoreCase(mainTopic, cChannel.getTopic())) {
                synchronized (this) {
                    cChannel.setTopic(mainParser.getChannel(cChannel.getName()).getTopic());
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelJoin(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c3*** %s@%s has joined %s", CODE_COLOUR, cChannelClient.getClient().getNickname(), getNetworkName(tParser), cChannel));
            }
        }

        for (String message : welcomeMessage) {
            tParser.sendNotice(cChannelClient.getClient().getNickname(), message);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelPart(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient, final String sReason) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c3*** %s@%s has left %s (%s)", CODE_COLOUR, cChannelClient.getClient().getNickname(), getNetworkName(tParser), cChannel, sReason));
            }
        }
    }
    
    /** {@inheritDoc} */
    @Override
    public void onChannelQuit(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient, final String sReason) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c3*** %s@%s has quit %s (%s)", CODE_COLOUR, cChannelClient.getClient().getNickname(), getNetworkName(tParser), cChannel, sReason));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelKick(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cKickedClient, final ChannelClientInfo cKickedByClient, final String sReason, final String sKickedByHost) {
        if (cKickedClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c7*** %s@%s was kicked from %s by %s@%3$s (%s)", CODE_COLOUR, cKickedClient.getClient().getNickname(), getNetworkName(tParser), cChannel, cKickedByClient.getClient().getNickname(), sReason));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelNickChanged(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChannelClient, final String sOldNick) {
        if (cChannelClient.getClient() == tParser.getLocalClient()) { return; }
        final char CODE_COLOUR = 3;
        for (Parser parser : getParsers()) {
            if (!parser.equals(tParser)) {
                parser.sendMessage(cChannel.getName(), String.format("%c7*** %s@%s is now %s@%3$s", CODE_COLOUR, sOldNick, getNetworkName(tParser), cChannelClient.getClient().getNickname()));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onChannelUserModeChanged(final Parser tParser, final ChannelInfo cChannel, final ChannelClientInfo cChangedClient, final ChannelClientInfo cSetByClient, final String sHost, final String sMode) {
        if (cChangedClient.getClient() == tParser.getLocalClient()) { return; }
        if (isMainParser(tParser)) { return; }

        final String thisNickname = cChangedClient.getClient().getNickname();
        final String myNickname = tParser.getLocalClient().getNickname();
        if (tParser.getStringConverter().equalsIgnoreCase(thisNickname, myNickname) && sMode.charAt(0) == '+') {
            // Try to set the topic!
            final String mainTopic;
            synchronized (this) {
                mainTopic = mainParser.getChannel(cChannel.getName()).getTopic();
            }
            if (!tParser.getStringConverter().equalsIgnoreCase(cChannel.getTopic(), mainTopic)) {
                cChannel.setTopic(mainTopic);
            }
        }
    }

    /**
     * Merge the given bits.
     *
     * @param bits Bits to merge
     * @param start Start
     * @param end end
     * @param joiner What to use to join them
     * @return Joined bits.
     */
    private String mergeBits(final String[] bits, final int start, final int end, final String joiner) {
        final StringBuilder builder = new StringBuilder();
        for (int i = start; i <= end; i++) {
            if (bits.length < i) { break; }
            if (i != start) { builder.append(joiner); }
            builder.append(bits[i]);
        }

        return builder.toString();
    }

    
    /**
     * Try to handle this as a command.
     * 
     * @param thisParser
     * @param message
     * @param channelClient
     * @param host
     * @return True if a command was run,
     */
    private boolean handleCommand(final Parser thisParser, final String message, final String host, final ChannelClientInfo channelClient) {
        final ChannelInfo thisChannel = (channelClient != null) ? channelClient.getChannel() : thisParser.getChannel(relayChannelName);
        if (thisChannel == null) { thisParser.joinChannel(relayChannelName); return false; }
        final ClientInfo thisClient = thisParser.getClient(host);
        final ChannelClientInfo thisChannelClient = (channelClient != null) ? channelClient : thisChannel.getChannelClient(thisClient);
        final String[] bits = message.split(" ");

        if (thisChannelClient == null) { return false; }

        final boolean isOp = (!thisChannelClient.getImportantMode().equalsIgnoreCase("v") && !thisChannelClient.getImportantMode().isEmpty());

        if (isMainParser(thisParser)) {
            // Opped users in the main channel can do magic!
            if (isOp) {
                if (bits[0].toLowerCase().equalsIgnoreCase("!sync")) {
                    final String mainTopic;
                    synchronized (this) {
                        mainTopic = mainParser.getChannel(thisChannel.getName()).getTopic();
                    }
                    for (Parser parser : getParsers()) {
                        if (!parser.equals(thisParser)) {
                            parser.getChannel(thisChannel.getName()).setTopic(mainTopic);
                        }
                    }

                    thisParser.sendNotice(thisClient.getNickname(), "Topics synced.");
                    return true;
                } else if (bits[0].toLowerCase().equalsIgnoreCase("!resettopic")) {
                    final String mainTopic;
                    synchronized (this) {
                        mainTopic = mainParser.getChannel(thisChannel.getName()).getTopic();
                    }
                    // The topic will be repeated back to it, and it will then
                    // resync it everywhere else.
                    thisChannel.setTopic(".");
                    thisChannel.setTopic(mainTopic);
                    thisParser.sendNotice(thisClient.getNickname(), "Topic reset.");
                    return true;
                } else if (bits[0].toLowerCase().equalsIgnoreCase("!topic") && bits.length > 1) {
                    final String newTopic = mergeBits(bits, 1, bits.length - 1, " ");
                    thisChannel.setTopic(newTopic);
                    thisParser.sendNotice(thisClient.getNickname(), "Topic set: "+newTopic);
                    return true;
                } else if (bits[0].toLowerCase().equalsIgnoreCase("!kick") && bits.length > 1) {
                    final String reason = mergeBits(bits, 2, bits.length - 1, " ");
                    final String person;
                    synchronized (this) { 
                        person = bits[1]+"@"+getNetworkName(mainParser);
                    }
                    final String[] personBits = person.split("@");
                    boolean kicked = false;

                    for (Parser parser : getParsers()) {
                        if (getNetworkName(parser).equalsIgnoreCase(personBits[1])) {
                            final ChannelClientInfo cci = parser.getChannel(thisChannel.getName()).getChannelClient(personBits[0]);
                            if (cci != null) {
                                thisParser.sendNotice(thisClient.getNickname(), "Kick attempted on "+getNetworkName(parser)+".");
                                kicked = true;
                                cci.kick(reason.isEmpty() ? "..." : reason);
                            } else {
                                thisParser.sendNotice(thisClient.getNickname(), "Unable to find user to kick on "+getNetworkName(parser)+".");
                                kicked = true;
                            }
                        }
                    }

                    if (!kicked) {
                        thisParser.sendNotice(thisClient.getNickname(), "Kick attempted.");
                    }
                    return true;
                } else if (bits[0].toLowerCase().equalsIgnoreCase("!rraw") && bits.length > 2 && isAdmin(thisClient, channelClient)) {
                    final String command = mergeBits(bits, 2, bits.length - 1, " ");

                    for (Parser parser : getParsers()) {
                        if (getNetworkName(parser).equalsIgnoreCase(bits[1])) {
                            parser.sendRawMessage(command);
                        }
                    }

                    thisParser.sendNotice(thisClient.getNickname(), "Sent command to "+bits[1]+": "+command);
                    return true;
                }
            }
        }

        if (isOp) {
            if (bits[0].toLowerCase().equalsIgnoreCase("!sync")) {
                final String mainTopic;
                synchronized (this) {
                    mainTopic = mainParser.getChannel(thisChannel.getName()).getTopic();
                }
                thisParser.getChannel(thisChannel.getName()).setTopic(mainTopic);

                thisParser.sendNotice(thisClient.getNickname(), "Topic synced.");
                return true;
            } else if (bits[0].toLowerCase().equalsIgnoreCase("!raw") && bits.length > 1 && isAdmin(thisClient, channelClient)) {
                final String rawMessage = mergeBits(bits, 1, bits.length - 1, " ");
                thisParser.sendRawMessage(rawMessage);
                thisParser.sendNotice(thisClient.getNickname(), "Sent raw: "+rawMessage);
                return true;
            }
        }

        if ((isOp || publicNames) && bits[0].toLowerCase().equalsIgnoreCase("!names") && bits.length > 1) {
            for (Parser parser : getParsers()) {
                if (getNetworkName(parser).equalsIgnoreCase(bits[1]) || bits[1].equalsIgnoreCase("*")) {
                    final StringBuilder names = new StringBuilder("");
                    final ChannelInfo ci = parser.getChannel(thisChannel.getName());

                    for (ChannelClientInfo cci : ci.getChannelClients()) {
                        names.append(" ");
                        names.append(cci.toString());
                    }

                    thisParser.sendNotice(thisClient.getNickname(), getNetworkName(parser)+" Names:"+names.toString());
                }
            }
            return true;
        }

        return false;
    }

    /** {@inheritDoc} */
    @Override
    public void onPrivateMessage(final Parser tParser, final String sMessage, final String sHost) {
        handleCommand(tParser, sMessage, sHost, null);
    }

    /** {@inheritDoc} */
    @Override
    public void onDataIn(final Parser tParser, final String sData) {
        System.out.println("<< "+sData);
    }

    /** {@inheritDoc} */
    @Override
    public void onDataOut(final Parser tParser, final String sData, final boolean bFromParser) {
        System.out.println(">> "+sData);
    }

    /** {@inheritDoc} */
    @Override
    public void onNickChanged(final Parser tParser, final ClientInfo cClient, final String sOldNick) {
        if (tParser.getStringConverter().equalsIgnoreCase(wantedNick, sOldNick)) {
            tParser.getLocalClient().setNickname(wantedNick);
        } else if (cClient == tParser.getLocalClient() && tParser.getStringConverter().equalsIgnoreCase(wantedNick, cClient.getNickname())) {
            sendOnConnect(tParser);
        }
    }

    /** {@inheritDoc} */
    @Override
    public void onQuit(final Parser tParser, final ClientInfo cClient, final String sReason) {
        if (tParser.getStringConverter().equalsIgnoreCase(wantedNick, cClient.getNickname())) {
            tParser.getLocalClient().setNickname(wantedNick);
        }
    }

    /**
     * Is the given user a bot admin?
     *
     * @param client Client to check for adminness!
     * @param channelClient Client to check for adminness!
     * @return True if the user is an admin, else false.
     */
    private boolean isAdmin(final ClientInfo client, final ChannelClientInfo channelClient) {
        final StringConverter sc = client.getParser().getStringConverter();
        final boolean isOp = (channelClient == null) ? false : (!channelClient.getImportantMode().equalsIgnoreCase("v") && !channelClient.getImportantMode().isEmpty());

        if (publicAdmin) {
            return isOp && sc.equalsIgnoreCase(channelClient.getChannel().getName(), relayChannelName);
        } else {
            return sc.equalsIgnoreCase(client.getHostname(), "home.dataforce.org.uk") || sc.equalsIgnoreCase(client.getNickname(), "Dataforce");
        }


    }
}
