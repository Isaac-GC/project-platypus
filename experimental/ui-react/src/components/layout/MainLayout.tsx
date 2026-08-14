import React from "react";
import Toolbar from "./Toolbar";
import { HorizontalSplit, VerticalSplit } from "./SplitPane";
import LeftPanel from "../panels/LeftPanel";
import CenterPanel from "../panels/CenterPanel";
import RightPanel from "../panels/RightPanel";
import BottomPanel from "../panels/BottomPanel";

const MainLayout: React.FC = () => {
  return (
    <div className="flex flex-col h-screen w-screen bg-vs-bg overflow-hidden">
      {/* Top toolbar */}
      <Toolbar />

      {/* Main content area */}
      <div className="flex-1 overflow-hidden">
        <VerticalSplit
          initialTopPct={72}
          minTopPx={200}
          minBottomPx={100}
          top={
            <HorizontalSplit
              initialLeftPct={22}
              initialRightPct={22}
              minLeftPx={150}
              minRightPx={150}
              minCenterPx={300}
              left={<LeftPanel />}
              center={<CenterPanel />}
              right={<RightPanel />}
            />
          }
          bottom={<BottomPanel />}
        />
      </div>
    </div>
  );
};

export default MainLayout;
