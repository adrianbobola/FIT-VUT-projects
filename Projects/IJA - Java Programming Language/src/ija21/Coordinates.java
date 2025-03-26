/*
  Class Cordinates represent x and y coordinates of object
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;

import java.util.Objects;

public class Coordinates extends Rectangle {

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Coordinates that = (Coordinates) o;
        return this.getX() == that.getX() && getY() == that.getY();
    }

    @Override
    public int hashCode() {
        return Objects.hash(getX(), getY());
    }

    /**
     * create new coordinates based on x and y values with transparent color
     *
     * @param x position on horizontal axis
     * @param y position on vertical axis
     */
    public Coordinates(int x, int y) {
        //transparent
        super(blockWidth.SCALE, blockWidth.SCALE, Color.TRANSPARENT);
        this.setX(x);
        this.setY(y);
    }

    /**
     * create new coordinates based on x and y values with specified color
     * @param x position on horizontal axis
     * @param y position on vertical axis
     * @param R red
     * @param G green
     * @param B blue
     */
    public Coordinates(int x, int y, double R, double G, double B) {
        super(blockWidth.SCALE, blockWidth.SCALE, Color.color(R, G, B));
        this.setStroke(Color.BLACK);
        this.setX(x);
        this.setY(y);
    }

    /**
     * @param cord coordinates of new object
     * @param R    red
     * @param G    green
     * @param B    blue
     */
    public Coordinates(Coordinates cord, double R, double G, double B) {
        super(blockWidth.SCALE, blockWidth.SCALE, Color.color(R, G, B));
        this.setStroke(Color.BLACK);
        this.setX((int) cord.getX());
        this.setY((int) cord.getY());
    }

    /**
     * get straight line distance between two coordinates
     *
     * @param cord 2.nd coordinate
     * @return distance of coordinates
     */
    public double getDistance(Coordinates cord) {
        return Math.sqrt(Math.pow(this.getX() - cord.getX(), 2) + Math.pow(this.getY() - cord.getY(), 2));
    }
}
