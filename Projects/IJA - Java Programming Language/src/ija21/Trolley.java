/*
  Class Trolley represent a trolley in the map.
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import javafx.scene.control.Label;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundFill;
import javafx.scene.paint.Color;
import javafx.scene.shape.Line;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Trolley extends Storeable {
    private final int id;
    private static final int capacity = 5;
    public boolean unload = false;

    public Map.Entry<String, Integer> task;
    public List<Coordinates> pathList;
    public Coordinates location;

    /**
     * Save trolley data into local structures task
     *
     * @param id_in trolley ID
     * @param cord  trolley coordinates (contains X and Y)
     */
    public Trolley(int id_in, Coordinates cord) {
        super(cord, 0, 0, 1);
        this.id = id_in;
        Label label = new Label();
        label.setBackground(new Background(new BackgroundFill(Color.WHITE, null, null)));

        List<Line> pathVisual = new ArrayList<>();
        this.setOnMouseEntered(mouseEvent -> {
            StringBuilder str = new StringBuilder("TROLLEY "+id+"\ncontains:");
            for (Map.Entry<String, Integer> item : this.getStored().entrySet()) {
                str.append("\n").append(item.getKey()).append(": ").append(item.getValue());
            }
            label.setText(str.toString());
            label.relocate((int) this.getX() + blockWidth.SCALE, (int) this.getY() + blockWidth.SCALE);
            GlobalScene.pane.getChildren().add(label);

            //midPoint of coordinate
            int mid = blockWidth.SCALE / 2;
            //make all lines
            if (pathList == null)
                return;
            for (int i = 0; i < pathList.size() - 1; i++) {
                Line l = new Line(pathList.get(i).getX() + mid, pathList.get(i).getY() + mid,
                        pathList.get(i + 1).getX() + mid, pathList.get(i + 1).getY() + mid);
                l.setStroke(Color.RED);
                pathVisual.add(l);
            }
            GlobalScene.pane.getChildren().addAll(pathVisual);
        });
        this.setOnMouseExited(mouseEvent -> {
            GlobalScene.pane.getChildren().remove(label);
            GlobalScene.pane.getChildren().removeAll(pathVisual);
            pathVisual.clear();
        });
    }

    /**
     * get amount of items in trolley
     * @return amount of items
     */
    public int getItemInCount() {
        int sum = 0;
        for (int count : this.getStored().values()) {
            sum += count;
        }
        return sum;
    }

    /**
     * remove all goods from trolley
     */
    public void unloadGoods() {
        for (Map.Entry<String, Integer> item : this.getStored().entrySet()) {
            this.delete_item(item.getKey(), item.getValue());
        }
        this.unload = false;
    }

    /**
     * get amount of additional items trolley can store
     * @return int free storage capacity of trolley
     */
    public int getRemainCapacity() {
        return capacity - this.getItemInCount();
    }

}
