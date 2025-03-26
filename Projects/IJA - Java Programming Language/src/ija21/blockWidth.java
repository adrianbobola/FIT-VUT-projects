/*
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

public class blockWidth {
    public static int SCALE = 15;

    /**
     * Apply zoom into SCALE which is using to show objects
     * @param zoom - zoom of scene
     */
    public static void setZOOM(Double zoom) {
        SCALE = (int) (zoom * 15);
    }
}