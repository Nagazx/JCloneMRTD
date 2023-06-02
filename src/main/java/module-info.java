module com.jclonemrtd.jclonemrtd {
    requires javafx.controls;
    requires javafx.fxml;
    requires java.smartcardio;
    requires scuba.smartcards;
    requires jmrtd;

    opens com.jclonemrtd.jclonemrtd to javafx.fxml;
    exports com.jclonemrtd.jclonemrtd;
}