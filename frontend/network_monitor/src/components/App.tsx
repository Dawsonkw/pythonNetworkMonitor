import Background from "./Background";
import ButtonContainer from "./ButtonContainer";
import Header from "./Header";
import ScreenContainer from "./ScreenContainer";
import DataDisplay from "./DataDisplay";
import DataScreen from "./DataScreen";
import Container from "./Container";

function App() {
  return (
    <>
      <Background />

      <Header />
      <Container>
        <ScreenContainer>
          <DataDisplay />
          <DataScreen />
        </ScreenContainer>
      </Container>

      <ButtonContainer></ButtonContainer>
    </>
  );
}

export default App;
