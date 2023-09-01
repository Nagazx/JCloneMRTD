package com.jclonemrtd.jclonemrtd;

import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardException;
import java.util.List;

public class Terminals {
    private TerminalFactory terminalFactory;
    private CardTerminal cardTerminal;

    public Terminals() {
        if (System.getProperty("os.name").startsWith("Mac"))
            System.setProperty("sun.security.smartcardio.library", "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC");
        this.terminalFactory = TerminalFactory.getDefault();
        this.cardTerminal = null;
    }
    public List<CardTerminal> getTerminals() throws CardException {
        return terminalFactory.terminals().list();
    }

    public CardTerminal getTerminal(int index) throws CardException {
        return this.getTerminals().get(index);
    }

    public void printTerminals() throws CardException {
        List<CardTerminal> terminals = this.getTerminals();
        for (int i = 0; i < terminals.size(); i++) {
            System.out.println(i + ": " + terminals.get(i));
        }
    }
    public void setCardTerminal(int index) throws  CardException{
        this.cardTerminal = this.getTerminal(index);
    }

    public CardTerminal getCardTerminal() {
        return this.cardTerminal;
    }
}