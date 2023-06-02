package com.jclonemrtd.jclonemrtd;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import org.jmrtd.PassportService;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.List;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException, CardException, CardServiceException {
        System.out.println("Hello world!");
        List<CardTerminal> terminalList = TerminalFactory.getDefault().terminals().list();
        terminalList.forEach(terminal -> {
            System.out.println(terminal.getName());
        });
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("hello-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
        //CardService cs = CardService.getInstance(terminal);
        //PassportService service = new PassportService(cs, PassportService.NORMAL_MAX_TRANCEIVE_LENGTH, PassportService.DEFAULT_MAX_BLOCKSIZE, true, false);
        //service.open();
        //BACKeySpec bacKey = new BACKey("12312312312312", "31121990", "311230");
    }

    public static void main(String[] args) {
        launch();
    }
}