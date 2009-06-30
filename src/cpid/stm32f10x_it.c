/******************** (C) COPYRIGHT 2007 STMicroelectronics ********************
* File Name          : stm32f10x_it.c
* Author             : MCD Application Team
* Date First Issued  : 05/21/2007
* Description        : Main Interrupt Service Routines.
*                      This file can be used to describe all the exceptions 
*                      subroutines that may occur within user application.
*                      When an interrupt happens, the software will branch 
*                      automatically to the corresponding routine.
*                      The following routines are all empty, user can write code 
*                      for exceptions handlers and peripherals IRQ interrupts.
********************************************************************************
* History:
* 05/21/2007: V0.1
********************************************************************************
* THE PRESENT SOFTWARE WHICH IS FOR GUIDANCE ONLY AIMS AT PROVIDING CUSTOMERS
* WITH CODING INFORMATION REGARDING THEIR PRODUCTS IN ORDER FOR THEM TO SAVE TIME.
* AS A RESULT, STMICROELECTRONICS SHALL NOT BE HELD LIABLE FOR ANY DIRECT,
* INDIRECT OR CONSEQUENTIAL DAMAGES WITH RESPECT TO ANY CLAIMS ARISING FROM THE
* CONTENT OF SUCH SOFTWARE AND/OR THE USE MADE BY CUSTOMERS OF THE CODING
* INFORMATION CONTAINED HEREIN IN CONNECTION WITH THEIR PRODUCTS.
*******************************************************************************/

/* Includes ------------------------------------------------------------------*/
#define _RTC
#include "common.h"
#include "commonCrypto.h"

#include "stm32f10x_it.h"

extern unsigned char powerState; // this comes from crypto.c
extern int penDown; // comes from hal.c
unsigned int penDownCooldown = 0;
unsigned int sampleDisplay = 1;  // flag to enable sampling (i.e. sample only outside of the cooldown window)
#define COOLDOWN_DELAY 3 // was 15 for a 30 ms delay, since systick runs at 500 Hz, now shorter
#define NUMSAMPS 5
#define PENUP_THRESH  3920  // was 3950
#define SETTLE_DELAY  100  // was 50
#define INVALID_HIGH  4050   // thresholds for rejecting a bad sample
#define INVALID_LOW   50

u16  arrayY[NUMSAMPS];
u16  arrayX[NUMSAMPS];
u16  xVal = 0;
u16  yVal = 0;
int  updated = 0;
u16  spiRegs[SPI_NUMREGS];

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/  
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/*******************************************************************************
* Function Name  : NMIException
* Description    : This function handles NMI exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void NMIException(void)
{
}

/*******************************************************************************
* Function Name  : HardFaultException
* Description    : This function handles Hard Fault exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void HardFaultException(void)
{
}

/*******************************************************************************
* Function Name  : MemManageException
* Description    : This function handles Memory Manage exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void MemManageException(void)
{
}

/*******************************************************************************
* Function Name  : BusFaultException
* Description    : This function handles Bus Fault exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void BusFaultException(void)
{
}

/*******************************************************************************
* Function Name  : UsageFaultException
* Description    : This function handles Usage Fault exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void UsageFaultException(void)
{
}

/*******************************************************************************
* Function Name  : DebugMonitor
* Description    : This function handles Debug Monitor exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DebugMonitor(void)
{
}

/*******************************************************************************
* Function Name  : SVCHandler
* Description    : This function handles SVCall exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void SVCHandler(void)
{
}

/*******************************************************************************
* Function Name  : PendSVC
* Description    : This function handles PendSVC exception.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void PendSVC(void)
{
}

/*******************************************************************************
* Function Name  : SysTickHandler
* Description    : This function handles SysTick Handler.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void settleDelay(void) {
  int i;
  for( i = 0; i < SETTLE_DELAY; i++ ) {
    // very short delay
  }
}

void SysTickHandler(void)
{
  GPIO_InitTypeDef GPIO_InitStructure;
  int sampCount = 0;
  int i;
  u16 max;
  u16 min;
  int maxIndex, minIndex;
  u32 avg;
  int count;
  u16 yTest;

  /* Disable SysTick Counter */
  SysTick_CounterCmd(SysTick_Counter_Disable);
  /* Clear SysTick Counter */
  SysTick_CounterCmd(SysTick_Counter_Clear);

  if( penDownCooldown < COOLDOWN_DELAY )
    penDownCooldown++;

  if( penDown == 0 ) {  // we think the pen is not down at all
    if( GPIO_ReadInputDataBit(GPIO_PNDWN_DET) == 0 ) { // 0 is the detected state, note inversion
      // this is the case that the pen goes down
      if( (penDown == 0) && (penDownCooldown >= COOLDOWN_DELAY) ) { // previously, we were not in a pen down
	if( powerState == 0 ) {
	  cmdPowerUp(); // power on if we were previously off!
	}
	GPIO_WriteBit(GPIO_PNDWN_OUT, Bit_SET);      
	penDownCooldown = 0;
	penDown = 1;
	sampleDisplay = 1;
      }
    }
  } else { // the pen was down, now we have to figure out if the pen is up
    // this is the case that the pen goes up
    ADC_RegularChannelConfig(ADC1, ADC_LCD_YP, 1, ADC_SampleTime_71Cycles5);
    ADC_SoftwareStartConvCmd(ADC1, ENABLE);
    while(ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC) == RESET)
      ;
    yTest = ADC_GetConversionValue(ADC1);
    if( (yTest > PENUP_THRESH) && (penDownCooldown >= COOLDOWN_DELAY) ) {
      GPIO_WriteBit(GPIO_PNDWN_OUT, Bit_RESET);
      penDownCooldown = 0;
      sampleDisplay = 0;
      penDown = 0;
    } else if ( (yTest > PENUP_THRESH) && (penDownCooldown < COOLDOWN_DELAY) ) {
      // penDownCooldown++; // this is implicit from the very, very top statement
      sampleDisplay = 0;
      penDown = 1;
      /* Enable the SysTick Counter */
      SysTick_CounterCmd(SysTick_Counter_Enable);
      return;  // exit the routine if we think we have chatter...
    } else {
      sampleDisplay = 1;
      penDownCooldown = 0; // force the cooldown to zero
      penDown = 1;
    }
  }

  if( penDown ) {
    if( sampleDisplay ) {
      // kick off the sense routine
      // turn off the pullup on pin 3 so as not to bias readings
      //    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_3;
      //    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING;
      //    GPIO_Init(GPIOA, &GPIO_InitStructure);

      GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz; // drive it hard
      //////////////////// sample the Y value (assume: pins 4/5 set for AIN on entry)
      // set LCD_XM to 0, LCD_XP to 1
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      GPIO_WriteBit(GPIO_LCD_XM, Bit_RESET);
      
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_7;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      GPIO_WriteBit(GPIO_LCD_XP, Bit_SET);
      
      settleDelay();
      /* ADC1 regular channel1 configuration */ 
      ADC_RegularChannelConfig(ADC1, ADC_LCD_YP, 1, ADC_SampleTime_71Cycles5);

      sampCount = 0;
      while( sampCount < NUMSAMPS ) {
	ADC_SoftwareStartConvCmd(ADC1, ENABLE);
	while(ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC) == RESET)
	  ;
	arrayY[sampCount++] = ADC_GetConversionValue(ADC1);
      }
      //////////////////// end sample the Y value

      //////////////////// sample the X value
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_7;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      
      // set LCD_YM to 0, LCD_YP to 1
      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_4;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      GPIO_WriteBit(GPIO_LCD_YM, Bit_RESET);

      GPIO_InitStructure.GPIO_Pin = GPIO_Pin_5;
      GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
      GPIO_Init(GPIOA, &GPIO_InitStructure);
      GPIO_WriteBit(GPIO_LCD_YP, Bit_SET);
    
      settleDelay();

      ADC_RegularChannelConfig(ADC1, ADC_LCD_XP, 1, ADC_SampleTime_71Cycles5);
      sampCount = 0;
      while( sampCount < NUMSAMPS ) {
	ADC_SoftwareStartConvCmd(ADC1, ENABLE);
	while(ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC) == RESET)
	  ;
	arrayX[sampCount++] = ADC_GetConversionValue(ADC1);
      }
      //////////////////// end sample the X value
    }

    //////////////////// return to pendown sampling mode
    // drive LCD_YM to 1 to discharge the display capacitance
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_4;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
    GPIO_Init(GPIOA, &GPIO_InitStructure);
    GPIO_WriteBit(GPIO_LCD_YM, Bit_SET);
    settleDelay();
    settleDelay();

    /* Configure PA.04 as analog input */ // Y-
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_4;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
    GPIO_Init(GPIOA, &GPIO_InitStructure);
    
    /* Configure PA.05 as analog input */ // Y+
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_5;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AIN;
    GPIO_Init(GPIOA, &GPIO_InitStructure);
    
    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_3;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IPU; // toggle to GPIO_Mode_IN_FLOATING when sampling
    GPIO_Init(GPIOA, &GPIO_InitStructure);

    GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
    GPIO_Init(GPIOA, &GPIO_InitStructure);
    GPIO_WriteBit(GPIO_LCD_XM, Bit_RESET);
    //////////////////// end return to pendown sampling mode

    ///////// verify that the pen was still down after all of this, or else discard data.
    settleDelay();
    ADC_RegularChannelConfig(ADC1, ADC_LCD_YP, 1, ADC_SampleTime_71Cycles5);
    ADC_SoftwareStartConvCmd(ADC1, ENABLE);
    while(ADC_GetFlagStatus(ADC1, ADC_FLAG_EOC) == RESET)
      ;
    yTest = ADC_GetConversionValue(ADC1);
    if( yTest > PENUP_THRESH ) {
      sampleDisplay = 0;  // other counters will get reset the next systick, which is fine
      // but we want to prevent commiting any data at this point in time
    }
    /////////

    if( sampleDisplay ) {
      // now perform data filtering
      max = 0;
      min = 65535;
      for( i = 0; i < NUMSAMPS; i++ ) {
	if( arrayX[i] > max ) {
	  max = arrayX[i];
	  maxIndex = i;
	}
	if( arrayX[i] < min ) {
	  min = arrayX[i];
	  minIndex = i;
	}
      }
      avg = 0;
      count = 0;
      for( i = 0; i < NUMSAMPS; i++ ) {
	if( (i != maxIndex) && (i != minIndex) ) {
	  avg += arrayX[i];
	  count ++; // note that in the case that I have exactly the same samples i get a different count...
	}
      }
      avg /= count;
      xVal = avg;
      updated |= 1;

      // now do the same for y
      max = 0;
      min = 65535;
      for( i = 0; i < NUMSAMPS; i++ ) {
	if( arrayY[i] > max ) {
	  max = arrayY[i];
	  maxIndex = i;
	}
	if( arrayY[i] < min ) {
	  min = arrayY[i];
	  minIndex = i;
	}
      }
      avg = 0;
      count = 0;
      for( i = 0; i < NUMSAMPS; i++ ) {
	if( (i != maxIndex) && (i != minIndex) ) {
	  avg += arrayY[i];
	  count ++; // note that in the case that I have exactly the same samples i get a different count...
	}
      }
      avg /= count;
      yVal = avg;
      
      updated |= 2;
      // the SPI routine should now be able to service with correct data
    }

  } else {
    // do nothing
  }

  /* Enable the SysTick Counter */
  SysTick_CounterCmd(SysTick_Counter_Enable);
}

/*******************************************************************************
* Function Name  : WWDG_IRQHandler
* Description    : This function handles WWDG interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void WWDG_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : PVD_IRQHandler
* Description    : This function handles PVD interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void PVD_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TAMPER_IRQHandler
* Description    : This function handles Tamper interrupt request. 
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TAMPER_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : RTC_IRQHandler
* Description    : This function handles RTC global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void RTC_IRQHandler(void)
{
  if( RTC_GetITStatus(RTC_IT_ALR) == SET ) {
    cmdPowerUp();  // it's a hard kick in the pants!
    
    RTC_ClearITPendingBit(RTC_IT_ALR);
  }
}

/*******************************************************************************
* Function Name  : FLASH_IRQHandler
* Description    : This function handles Flash interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void FLASH_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : RCC_IRQHandler
* Description    : This function handles RCC interrupt request. 
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void RCC_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : EXTI0_IRQHandler
* Description    : This function handles External interrupt Line 0 request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI0_IRQHandler(void)
{
 if(EXTI_GetITStatus(EXTI_Line0) != RESET)
  {
    if( powerState == 0 ) {  // if we are powered down...
      cmdPowerUp();  // then power up
      while( GPIO_ReadInputDataBit(GPIO_POWERSWITCH) )
	;  // wait until button released...
      wait_ms(50); // debounce time, 50 ms
    } else {  // if we are powered up...
      cmdPowerDown(); // then power down
      while( GPIO_ReadInputDataBit(GPIO_POWERSWITCH) )
	;  // wait until button released...
      wait_ms(50); // debounce time, 50 ms
    }
    /* Clear the EXTI line 0 pending bit */
    EXTI_ClearITPendingBit(EXTI_Line0);
  }
  
}

/*******************************************************************************
* Function Name  : EXTI1_IRQHandler
* Description    : This function handles External interrupt Line 1 request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI1_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : EXTI2_IRQHandler
* Description    : This function handles External interrupt Line 2 request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI2_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : EXTI3_IRQHandler
* Description    : This function handles External interrupt Line 3 request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI3_IRQHandler(void)
{

#if 0
  // is this redundant?? because of the systick...i think we should delete this
  // and also shut down this interrupt behavior
  // but for now we leave it around just in case we have to put the code back in
  if( GPIO_ReadInputDataBit(GPIO_PNDWN_DET) == 0 ) {
    penDown = 1;
  } else {
    penDown = 0;
  }
#endif

}

/*******************************************************************************
* Function Name  : EXTI4_IRQHandler
* Description    : This function handles External interrupt Line 4 request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI4_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel1_IRQHandler
* Description    : This function handles DMA Stream 1 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel1_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel2_IRQHandler
* Description    : This function handles DMA Stream 2 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel2_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel3_IRQHandler
* Description    : This function handles DMA Stream 3 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel3_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel4_IRQHandler
* Description    : This function handles DMA Stream 4 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel4_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel5_IRQHandler
* Description    : This function handles DMA Stream 5 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel5_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel6_IRQHandler
* Description    : This function handles DMA Stream 6 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel6_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : DMAChannel7_IRQHandler
* Description    : This function handles DMA Stream 7 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void DMAChannel7_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : ADC_IRQHandler
* Description    : This function handles ADC global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void ADC_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : USB_HP_CAN_TX_IRQHandler
* Description    : This function handles USB High Priority or CAN TX interrupts 
*                  requests.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USB_HP_CAN_TX_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : USB_LP_CAN_RX0_IRQHandler
* Description    : This function handles USB Low Priority or CAN RX0 interrupts 
*                  requests.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USB_LP_CAN_RX0_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : CAN_RX1_IRQHandler
* Description    : This function handles CAN RX1 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void CAN_RX1_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : CAN_SCE_IRQHandler
* Description    : This function handles CAN SCE interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void CAN_SCE_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : EXTI9_5_IRQHandler
* Description    : This function handles External lines 9 to 5 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI9_5_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM1_BRK_IRQHandler
* Description    : This function handles TIM1 Break interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM1_BRK_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM1_UP_IRQHandler
* Description    : This function handles TIM1 overflow and update interrupt 
*                  request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM1_UP_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM1_TRG_COM_IRQHandler
* Description    : This function handles TIM1 Trigger and Commutation interrupts 
*                  requests.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM1_TRG_COM_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM1_CC_IRQHandler
* Description    : This function handles TIM1 capture compare interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM1_CC_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM2_IRQHandler
* Description    : This function handles TIM2 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM2_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM3_IRQHandler
* Description    : This function handles TIM3 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM3_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : TIM4_IRQHandler
* Description    : This function handles TIM4 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void TIM4_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : I2C1_EV_IRQHandler
* Description    : This function handles I2C1 Event interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void I2C1_EV_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : I2C1_ER_IRQHandler
* Description    : This function handles I2C1 Error interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void I2C1_ER_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : I2C2_EV_IRQHandler
* Description    : This function handles I2C2 Event interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void I2C2_EV_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : I2C2_ER_IRQHandler
* Description    : This function handles I2C2 Error interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void I2C2_ER_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : SPI1_IRQHandler
* Description    : This function handles SPI1 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void SPI1_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : SPI2_IRQHandler
* Description    : This function handles SPI2 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void SPI2_IRQHandler(void)
{
  u16 rxData;
  u16 rxAdr;
  // if i get here, i got an SPI transaction in.
  // ASSUME: I only get here when whole, proper SPI transactions are completed
  // ASSUME: because I do processing on the fly, make sure you don't clock SPI faster than say, 1 MHz
  // this implies that I will never have to deal with an underrun situation....

  // first update the register set with fresh data
  spiRegs[SPI_REGADR_CTL] = updated;
  if( (xVal < INVALID_HIGH) && (xVal > INVALID_LOW) &&  // only update if the sample isn't bad.
      (yVal < INVALID_HIGH) && (yVal > INVALID_LOW) ) {
    spiRegs[SPI_REGADR_X] = xVal;
    spiRegs[SPI_REGADR_Y] = yVal;
  } else {
    spiRegs[SPI_REGADR_CTL] = 0; // no update if there were bad samples
  }

  rxData = SPI_ReceiveData(SPI2);

  rxAdr = (rxData & ADR_FIELD_MASK) >> ADR_FIELD_OFF;
  // now decode it
  if( (rxData & RW_FLAG_MASK) >> RW_FLAG_OFF == SPI_READ_OP ) {
    // read op
    if( rxAdr < SPI_NUMREGS && rxAdr >= 0) { // right of && is redundant but be safe...
      /* Send SPI2 data */
      SPI_SendData(SPI2, spiRegs[rxAdr]); // this merely writes this data into the DR
      // it's actually transmitted on the next cycle automatically
    }
    // if we read X or Y reset the updated fields
    if( rxAdr == SPI_REGADR_X )
      updated &= ~0x1;
    if( rxAdr == SPI_REGADR_Y )
      updated &= ~0x2;

  } else {
    // write op
    if( rxAdr < SPI_NUMREGS && rxAdr >= 0) { // right of && is redundant but be safe...
      // only commit if the address is in range
      spiRegs[rxAdr] = (rxData & DAT_FIELD_MASK) >> DAT_FIELD_OFF;
    }
  }
}

/*******************************************************************************
* Function Name  : USART1_IRQHandler
* Description    : This function handles USART1 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USART1_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : USART2_IRQHandler
* Description    : This function handles USART2 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USART2_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : USART3_IRQHandler
* Description    : This function handles USART3 global interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USART3_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : EXTI15_10_IRQHandler
* Description    : This function handles External lines 15 to 10 interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void EXTI15_10_IRQHandler(void)
{
 if(EXTI_GetITStatus(EXTI_Line10) != RESET)
  {
    setRunMode();  // wake up the CP on serial interrupt
    /* Clear the EXTI line 10 pending bit */
    EXTI_ClearITPendingBit(EXTI_Line10);
  }

}

/*******************************************************************************
* Function Name  : RTCAlarm_IRQHandler
* Description    : This function handles RTC Alarm interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void RTCAlarm_IRQHandler(void)
{
}

/*******************************************************************************
* Function Name  : USBWakeUp_IRQHandler
* Description    : This function handles USB WakeUp interrupt request.
* Input          : None
* Output         : None
* Return         : None
*******************************************************************************/
void USBWakeUp_IRQHandler(void)
{
}

/******************* (C) COPYRIGHT 2007 STMicroelectronics *****END OF FILE****/
