/*
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.Pane;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import javafx.event.EventHandler;

import java.util.HashMap;
import java.util.Map;

/**
 * Main class
 */
public class Main extends Application {
    // default values
    int mapSpeed = 100;
    double mapZOOM = 1.0;
    boolean pausedScene = false;
    boolean scenePlaying = false;
    Pane root;
    Scene scene;
    Controller controller;
    RequirementsParser reqParserDefault = requirementsProcessing();

    @Override
    public void start(Stage primaryStage) {
        root = new Pane();
        root.setStyle("-fx-background-color: darkgrey;");
        primaryStage.setTitle("IJA 2020/21 - Project");

        //load shelfs
        JsonParser jsonParser = jsonParsing();

        //Get all global requirements into local
        Map<String, Integer> reqParser = new HashMap<>();
        reqParser.putAll(reqParserDefault.getRequirements());
        controller = new Controller(root, jsonParser, reqParser, blockWidth.SCALE);

        // scene window params
        int windowWidth = 800;
        int windowLength = 1400;
        addButtons(windowWidth - 40, windowLength, primaryStage);
        scene = new Scene(root, windowLength, windowWidth);
        primaryStage.setScene(scene);
        primaryStage.show();

        // user closed scene windows -> exit(0)
        primaryStage.setOnCloseRequest(new EventHandler<WindowEvent>() {
            public void handle(WindowEvent we) {
                primaryStage.close();
                System.exit(0);
            }
        });

    }

    /**
     * Parsing Map objects from input file
     *
     * @return Parsed all maps objects
     */
    public static JsonParser jsonParsing() {
        JsonParser jsonParser = null;
        try {
            jsonParser = new JsonParser("data/sample.json", blockWidth.SCALE);
        } catch (Exception e) {
            System.err.println("parser error: sample.json");
            System.exit(1);
        }
        return jsonParser;
    }

    /**
     * Parsing all requirements from input file of from user input (If file data/requirements.json missing)
     *
     * @return Parsed all requirements
     */
    public static RequirementsParser requirementsProcessing() {
        RequirementsParser reqParser = null;
        try {
            reqParser = new RequirementsParser("data/requirements.json");
        } catch (Exception e) {
            System.err.println("requirements input error");
            System.exit(2);
        }

        System.out.println("----- requirements: ------");
        reqParser.getRequirements().forEach(
                (name, count) -> System.out.println(name + ", " + count + " pcs"));
        System.out.println("----------------------------------------------------------------");

        return reqParser;
    }

    public static void main(String[] args) {
        launch(args);
    }

    /**
     * Function puts all buttons into scene
     *
     * @param ySur         - Y - Position of buttons in scene
     * @param xSur         - Max windowLength of scene
     * @param primaryStage - Scenes stage
     */
    public void addButtons(int ySur, int xSur, Stage primaryStage) {
        //show MapSpeed
        Button buttonDisplaySpeed = new Button(Integer.toString(mapSpeed));
        buttonDisplaySpeed.setStyle("-fx-border-color: #000200; -fx-border-width: 5px;");
        buttonDisplaySpeed.setLayoutX(70);
        buttonDisplaySpeed.setLayoutY(ySur);
        root.getChildren().add(buttonDisplaySpeed);
        buttonDisplaySpeed.setOnAction(event1 -> {
            mapSpeed = 500;
            buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
        });

        //PAUSE button
        Button buttonPause = new Button("PAUSE");
        buttonPause.setStyle("-fx-border-color: #1E5D1F; -fx-border-width: 5px;");
        buttonPause.setLayoutX(260);
        buttonPause.setLayoutY(ySur);
        buttonPause.setOnAction(event1 -> {
            if (!pausedScene && scenePlaying) {
                controller.stop();
                pausedScene = true;
                buttonPause.setText("RESUME");
            } else if (pausedScene) {
                buttonPause.setText("PAUSE");
                controller.play(mapSpeed);
                pausedScene = false;
            }
        });

        //SPEED+ button
        Button buttonSpeedInc = new Button("+ Speed");
        buttonSpeedInc.setStyle("-fx-border-color: #8DC53F; -fx-border-width: 5px;");
        buttonSpeedInc.setLayoutX(120);
        buttonSpeedInc.setLayoutY(ySur);
        buttonSpeedInc.setOnAction(event1 -> {
            if (mapSpeed == 1) {
                mapSpeed = 5;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 5) {
                mapSpeed = 10;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 10) {
                mapSpeed = 25;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 25) {
                mapSpeed = 50;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 50) {
                mapSpeed = 100;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 100) {
                mapSpeed = 250;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 250) {
                mapSpeed = 500;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 500) {
                mapSpeed = 750;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 750) {
                mapSpeed = 1000;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            }
            if (!pausedScene && scenePlaying) {
                controller.stop();
                pausedScene = true;
                buttonPause.setText("RESUME");
                root.getChildren().remove(buttonPause);
                root.getChildren().add(buttonPause);
            }
        });
        root.getChildren().add(buttonSpeedInc);

        //SPEED- button
        Button buttonSpeedDec = new Button("- Speed");
        buttonSpeedDec.setStyle("-fx-border-color: #1E5D1F; -fx-border-width: 5px;");
        buttonSpeedDec.setLayoutX(0);
        buttonSpeedDec.setLayoutY(ySur);
        buttonSpeedDec.setOnAction(event1 -> {
            if (mapSpeed == 1000) {
                mapSpeed = 750;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 750) {
                mapSpeed = 500;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 500) {
                mapSpeed = 250;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 250) {
                mapSpeed = 100;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 100) {
                mapSpeed = 50;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 50) {
                mapSpeed = 25;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 25) {
                mapSpeed = 10;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 10) {
                mapSpeed = 5;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            } else if (mapSpeed == 5) {
                mapSpeed = 1;
                buttonDisplaySpeed.setText(Integer.toString(mapSpeed));
            }
            if (!pausedScene && scenePlaying) {
                controller.stop();
                pausedScene = true;
                buttonPause.setText("RESUME");
                root.getChildren().remove(buttonPause);
                root.getChildren().add(buttonPause);
            }
        });
        root.getChildren().add(buttonSpeedDec);

        //SHOW ZOOM
        Button buttonDisplayZOOM = new Button(Double.toString(mapZOOM));
        buttonDisplayZOOM.setStyle("-fx-border-color: #000200; -fx-border-width: 5px;");
        buttonDisplayZOOM.setLayoutX(xSur - 110);
        buttonDisplayZOOM.setLayoutY(ySur);
        root.getChildren().add(buttonDisplayZOOM);
        buttonDisplayZOOM.setOnAction(event1 -> {
            mapZOOM = 1.0;
            buttonDisplayZOOM.setText(Double.toString(mapZOOM));
        });

        //ZOOM+ button
        Button buttonZoomInc = new Button("+ZOOM");
        buttonZoomInc.setStyle("-fx-border-color: #0037FE; -fx-border-width: 5px;");
        buttonZoomInc.setLayoutX(xSur - 70);
        buttonZoomInc.setLayoutY(ySur);
        buttonZoomInc.setOnAction(event1 -> {
            if (mapZOOM == 0.25) {
                mapZOOM = 0.50;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 0.50) {
                mapZOOM = 1.0;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 1.0) {
                mapZOOM = 1.5;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 1.5) {
                mapZOOM = 2.0;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            }
        });
        root.getChildren().add(buttonZoomInc);

        //ZOOM- button
        Button buttonZoomDec = new Button("-ZOOM");
        buttonZoomDec.setStyle("-fx-border-color: #7F9AFE; -fx-border-width: 5px;");
        buttonZoomDec.setLayoutX(xSur - 180);
        buttonZoomDec.setLayoutY(ySur);
        buttonZoomDec.setOnAction(event1 -> {
            if (mapZOOM == 2.0) {
                mapZOOM = 1.5;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 1.5) {
                mapZOOM = 1.0;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 1.0) {
                mapZOOM = 0.50;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            } else if (mapZOOM == 0.50) {
                mapZOOM = 0.25;
                blockWidth.setZOOM(mapZOOM);
                buttonDisplayZOOM.setText(Double.toString(mapZOOM));
            }
        });
        root.getChildren().add(buttonZoomDec);

        //RESET button
        Button buttonReset = new Button("RESET");
        buttonReset.setStyle("-fx-border-color: #FE2D2D; -fx-border-width: 5px;");
        buttonReset.setLayoutX(330);
        buttonReset.setLayoutY(ySur);
        buttonReset.setOnAction(event1 -> {
            controller.stop();
            pausedScene = false;
            scenePlaying = false;
            buttonPause.setText("PAUSE");
            start(primaryStage);
        });

        //PLAY button
        Button buttonPlay = new Button("PLAY");
        buttonPlay.setStyle("-fx-border-color: #3BB83E; -fx-border-width: 5px;");
        buttonPlay.setLayoutX(200);
        buttonPlay.setLayoutY(ySur);
        buttonPlay.setOnAction(event1 -> {
            if (pausedScene) {
                buttonPause.setText("PAUSE");
                controller.play(mapSpeed);
                pausedScene = false;
                //multi-clicking play button secure
            } else if (!scenePlaying) {
                start(primaryStage);
                buttonPause.setText("PAUSE");
                controller.start(mapSpeed);
                scenePlaying = true;
                root.getChildren().add(buttonPause);
                root.getChildren().add(buttonReset);
            }
        });
        root.getChildren().add(buttonPlay);

        //EXIT button
        Button buttonExit = new Button("EXIT");
        buttonExit.setStyle("-fx-border-color: #FE2D2D; -fx-border-width: 5px;");
        buttonExit.setLayoutX(450);
        buttonExit.setLayoutY(ySur);
        buttonExit.setOnAction(event1 -> {
            System.exit(0);
        });
        root.getChildren().add(buttonExit);
    }
}