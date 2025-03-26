/*
  Class Shelf
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import javafx.scene.control.Label;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundFill;
import javafx.scene.paint.Color;

import java.util.Map;

public class Shelf extends Storeable {

    /**
     * new shelf item with mouse listener, to show useful information on hover
     * @param cord positional coordinates of new shelf
     */
    public Shelf(Coordinates cord) {
        super(cord, 0, 1, 0);
        Label label = new Label();
        label.setBackground(new Background(new BackgroundFill(Color.WHITE, null, null)));

        this.setOnMouseEntered(mouseEvent -> {
            StringBuilder str = new StringBuilder("SHELF \ncontains:");
            for (Map.Entry<String, Integer> item : this.getStored().entrySet()) {
                str.append("\n").append(item.getKey()).append(": ").append(item.getValue());
            }
            label.setText(str.toString());
            label.relocate((int) this.getX() + blockWidth.SCALE, (int) this.getY() + blockWidth.SCALE);
            GlobalScene.pane.getChildren().add(label);
        });
        this.setOnMouseExited(mouseEvent -> {
            GlobalScene.pane.getChildren().remove(label);
        });
    }
}
