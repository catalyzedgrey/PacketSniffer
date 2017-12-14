package src;

import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.application.Application;

public class Main extends Application {

    private Scene scene;
    public static Stage stage;

    @Override
    public void start(Stage stage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("../main.fxml"));
        scene = new Scene(root, 1280, 720);
        scene.setFill(Color.OLDLACE);
        stage.setTitle("ABC PACKET SNIFFER");
        stage.setScene(scene);
        stage.show();
        this.stage = stage;
    }

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void stop() {
        System.exit(0);
    }
}
