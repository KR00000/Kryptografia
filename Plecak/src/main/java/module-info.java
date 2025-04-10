module org.example.plecak {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;


    opens org.example.plecak to javafx.fxml;
    exports org.example.plecak;
}