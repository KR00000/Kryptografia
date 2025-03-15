module org.example.kryptografia {
    requires javafx.controls;
    requires javafx.fxml;


    opens org.example.kryptografia to javafx.fxml;
    exports org.example.kryptografia;
}