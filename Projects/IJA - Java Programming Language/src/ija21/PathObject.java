/*
  Class PathObject
  @author Ladislav Dokoupil (xdokou14)
  @author Adrián Bobola (xbobol00)
 */

package ija21;

public class PathObject extends Coordinates {

    /**
     * new path object used for creating obstacles.
     * object transforms on click into empty shelf.
     * @param cord positional coordinates of new shelf
     * @param c controller reference to update all objects
     */
    public PathObject(Coordinates cord, Controller c) {
        super((int) cord.getX(), (int) cord.getY());
        this.setOnMouseClicked(mouseEvent -> {
            c.jsonParser.addShelf(cord);
            c.root.getChildren().add(c.jsonParser.getAllShelfs().getOrDefault(cord, new Shelf(cord)));
            c.findPath.updatePaths(c.jsonParser.getAllShelfs());
            //invalidate all set paths
            for (Trolley t : c.jsonParser.getTrolleys()) {
                t.pathList = null;
            }
        });
    }
}
