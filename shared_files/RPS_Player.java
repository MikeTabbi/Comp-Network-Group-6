import java.util.Random;

public class RPS_Player {
    private int numberOfGamesWon;
    private int numberOfGamesPlayed;
    private int choice;
    private String name;

    public RPS_Player(String name){
        this.name=name;
    }

    public String getName(){
        return name;
    }

    /**
     * Returns the number of games played since a clear() was issued.
     * @return returns the number of games played.
     */
    public int getNumberOfGamesPlayed(){
        return numberOfGamesPlayed*2;
    }

    /**
     * Returns the number of games won since a clear() was issued.
     * @return returns the number of games won.
     */
    public int getNumberOfGamesWon(){
        return numberOfGamesWon;
    }

    /**
     * Returns the win percentage as number between 0 and 1.
     * @return win percentage as a double.
     */
    public double getWinPercentage(){
        if(numberOfGamesPlayed==0){
            return 0.0;
        }
        return (double)numberOfGamesWon/numberOfGamesPlayed;
    }

    /**
     * Starts a new game.
     */
    public void clear(){
        numberOfGamesPlayed=0;
        numberOfGamesWon=0;
    }

    /**
     * This player challenges anotherPlayer whereby both players make a
     * random choice of rock, paper, scissors.  A reference to the winning
     * player is returned or null if there is a draw.
     * @param anotherPlayer an RPS_Player that this player is challenging.
     * @return Reference to the RPS_Player that won or a null if there is a draw
     */
    public RPS_Player challenge(RPS_Player anotherPlayer){
        if(choice == -1){
            Random random = new Random();
            choice = random.nextInt(3);
        }
        numberOfGamesPlayed++;

        if (anotherPlayer.choice==-1){
            Random random = new Random();
            anotherPlayer.choice = random.nextInt(3);
            anotherPlayer.numberOfGamesPlayed++;
        }
        if(choice== anotherPlayer.choice){
            return null;
        }else if((choice==0&&anotherPlayer.choice==2)||(choice==2&&anotherPlayer.choice==0)||(choice==2 &&anotherPlayer.choice==1)){
            this.numberOfGamesWon++;
            return this;
        } else{
            anotherPlayer.numberOfGamesWon++;
            return anotherPlayer;
        }


    }

    /**
     * This player challenges anotherPlayer whereby this player uses the previous
     * choice made and anotherPlayer makes a random choice of rock, paper, scissors.
     * A reference to the winning player is returned or null if there is a draw.
     * @param anotherPlayer an RPS_Player that this player is challenging.
     * @return Reference to the RPS_Player that won or a null if there is a draw
     */
    public RPS_Player keepAndChallenge(RPS_Player anotherPlayer){
        if(choice == -1){
            Random random = new Random();
            choice = random.nextInt(3);
        }
        numberOfGamesPlayed++;

        if (anotherPlayer.choice==-1){
            Random random = new Random();
            anotherPlayer.choice = random.nextInt(3);
            anotherPlayer.numberOfGamesPlayed++;
        }
        if(choice== anotherPlayer.choice){
            return null;
        }else if((choice==0&&anotherPlayer.choice==2)||(choice==2&&anotherPlayer.choice==0)||(choice==2 &&anotherPlayer.choice==1)){
            this.numberOfGamesWon++;
            return this;
        } else{
            anotherPlayer.numberOfGamesWon++;
            return anotherPlayer;
        }
    }

}
